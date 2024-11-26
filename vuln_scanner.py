import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from flask import Flask, Response, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from sqlalchemy import desc
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO
import pymysql

# Ensure PyMySQL works with SQLAlchemy
pymysql.install_as_MySQLdb()

app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "*"}})  # Enable CORS for scan route

# Configuration for database and security
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:admin@localhost/users'  # custom based on machine
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
if(db):
    print("True")
else:
    print("False")
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Logging configuration
logging.basicConfig(level=logging.INFO)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    open_ports = db.Column(db.JSON, nullable=True)
    headers = db.Column(db.JSON, nullable=True)
    encryption_strength = db.Column(db.JSON, nullable=True)
    vulnerabilities = db.Column(db.JSON, nullable=True)
    additional_info = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('scans', lazy=True))

# Registration form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

    def validate_passwords(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

# Login form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route to the home page, redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/reports')
def report_history():
    # Fetch all reports for the current user, sorted by timestamp (newest to oldest)
    user_reports = Scan.query.filter_by(user_id=current_user.id).order_by(desc(Scan.scan_date)).all()

    # Format the reports for display
    reports = [{
        "id": report.id,
        "target": report.target,
        "timestamp": report.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": report.open_ports,
        "headers": report.headers,
        "encryption_strength": report.encryption_strength,
        "additional_info": report.additional_info
    } for report in user_reports]

    # Render the reports.html template with user-specific reports
    return render_template('reports.html', reports=reports)


# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))  # Ensure 'index' route exists
        flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)

# Route for the index page
@app.route('/index')
@login_required
def index():
    return render_template('index.html')


# Route for logging out
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! You can now login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Check for common security headers in the HTTP response.
def check_headers(target_url):
    headers = {}
    try:
        response = requests.get(target_url, timeout=5)
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]
        for header in security_headers:
            headers[header] = response.headers.get(header, "Not Set")
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP request failed: {e}")
        return {"error": f"HTTP request failed: {e}"}
    return headers

# Scans a single port to check if it's open.
def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                return port
    except Exception as e:
        logging.error(f"Error scanning port {port} on host {host}: {e}")
    return None

# Helper function to get SSL/TLS information
def get_encryption_info(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as sock:
            sock.connect((hostname, port))
            cipher = sock.cipher()
            if cipher:
                cipher_name, protocol_version, key_exchange_strength = cipher
                strength = (
                    "Strong" if key_exchange_strength >= 256 else
                    "Moderate" if key_exchange_strength >= 128 else
                    "Weak"
                )
                return {
                    "cipher": cipher_name,
                    "protocol_version": protocol_version,
                    "key_exchange_strength": str(key_exchange_strength) + " bits",
                    "strength": strength
                }
            else:
                return {
                    "cipher": "undefined",
                    "protocol_version": "undefined",
                    "key_exchange_strength": "undefined",
                    "strength": "undefined",
                    "error": "Cipher information could not be retrieved."
                }
    except Exception as e:
        return {
            "cipher": "undefined",
            "protocol_version": "undefined",
            "key_exchange_strength": "undefined",
            "strength": "undefined",
            "error": str(e)
        }

# Route to analyze the key exchange strength for both the user-specified server and local network
@app.route("/check_encryption_strength", methods=["POST"])
def check_encryption_strength():
    server_url = request.json.get("server_url")
    hostname = server_url.replace("https://", "").replace("http://", "").split("/")[0]
    remote_server_info = get_encryption_info(hostname)
    local_network_info = get_encryption_info("www.google.com")
    return jsonify({
        "remote_server_info": remote_server_info,
        "local_network_info": local_network_info
    })

# Route for performing the scan
@app.route("/scan", methods=["POST"])
@login_required
def scan():
    target = request.form["target"].strip()
    port_start = int(request.form.get("port_start", 1))
    port_end = int(request.form.get("port_end", 1024))

    # Extract hostname from URL
    target_host = urlparse(target).hostname or target

    logging.info(f"Scanning target: {target_host} from port {port_start} to {port_end}")

    # Check headers
    headers = check_headers(target)

    # Scan ports using threading
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(
            executor.map(
                lambda p: scan_port(target_host, p), range(port_start, port_end + 1)
            )
        )
        open_ports = [port for port in results if port]

    logging.info(f"Open ports: {open_ports}")
    return jsonify({"headers": headers, "open_ports": open_ports})

@app.route('/download_report/<int:report_id>', methods=['GET'])
@login_required
def download_report(report_id):
    # Fetch the specific report
    report = Scan.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()

    # Create the PDF in memory
    buffer = BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    # Sample stylesheet for formatting
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    section_style = styles['Heading2']
    normal_style = styles['BodyText']

    # Add the header with the user's full name and scan date
    title = f"Scan Report for {current_user.username} on {report.scan_date.strftime('%Y-%m-%d')}"
    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 12))

    # Add the target and scan details
    elements.append(Paragraph("Scan Details", section_style))
    scan_details = [
        ["Target:", report.target],
        ["Date of Scan:", report.scan_date.strftime('%Y-%m-%d %H:%M:%S')],
        ["Open Ports:", ", ".join(map(str, report.open_ports)) if report.open_ports else "None"],
    ]
    scan_table = Table(scan_details, colWidths=[150, 350])
    scan_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(scan_table)
    elements.append(Spacer(1, 12))

    # Add headers section
    elements.append(Paragraph("HTTP Headers", section_style))
    headers = report.headers or {}
    for key, value in headers.items():
        elements.append(Paragraph(f"{key}: {value}", normal_style))
    elements.append(Spacer(1, 12))

    # Add encryption strength section
    elements.append(Paragraph("Encryption Strength", section_style))
    encryption = report.encryption_strength or {}
    for key, value in encryption.items():
        elements.append(Paragraph(f"{key}: {value}", normal_style))
    elements.append(Spacer(1, 12))

    # Add vulnerabilities section
    elements.append(Paragraph("Vulnerabilities", section_style))
    vulnerabilities = report.vulnerabilities or []
    if vulnerabilities:
        for vuln in vulnerabilities:
            elements.append(Paragraph(f"CVE: {vuln.get('cve', 'Unknown')} - {vuln.get('description', 'No description')}", normal_style))
    else:
        elements.append(Paragraph("No vulnerabilities detected.", normal_style))
    elements.append(Spacer(1, 12))

    # Add additional info section
    elements.append(Paragraph("Additional Information", section_style))
    elements.append(Paragraph(report.additional_info or "No additional information provided.", normal_style))
    elements.append(Spacer(1, 12))

    # Build the PDF
    pdf.build(elements)

    # Return the PDF as a response
    buffer.seek(0)
    return Response(
        buffer,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename=report_{report.id}.pdf'
        }
    )

if __name__ == "__main__":
    # Create the tables (make sure the database exists)
    with app.app_context():
        db.create_all()

    app.run(debug=True)
