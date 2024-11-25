import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import pymysql
import json
import cryptography

# Ensure PyMySQL works with SQLAlchemy
pymysql.install_as_MySQLdb()

app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "*"}})  # Enable CORS for scan route

# Configuration for database and security
credentials_file = 'db_credentials.json'  # Keeps sensitive info off of git
try:
    with open(credentials_file, 'r') as f:
        credentials = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    credentials = {
        'host': input('Database Host: '),
        'port': input('Port: '),
        'username': input('Username: '),
        'password': input('Password: '),
        'db_name': input('Database Name: ')
    }
    with open(credentials_file, 'w') as f:
        json.dump(credentials, f, indent=4)

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{credentials['username']}:{credentials['password']}@{credentials['host']}:{credentials['port']}/{credentials['db_name']}"
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
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
def reports():
    return render_template('reports.html')


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

if __name__ == "__main__":
    # Create the tables (make sure the database exists)
    with app.app_context():
        db.create_all()

    app.run(debug=True)
