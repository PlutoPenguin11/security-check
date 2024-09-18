from flask import Flask, render_template, request, jsonify
import socket
import requests

app = Flask(__name__)

# Function to scan for open ports on a target
def scan_ports(target):
    open_ports = []
    for port in range(1, 1024):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

# Function to check for basic security headers
def check_headers(target_url):
    headers = {}
    try:
        response = requests.get(target_url)
        headers['X-Frame-Options'] = response.headers.get('X-Frame-Options', 'Not Set')
        headers['X-Content-Type-Options'] = response.headers.get('X-Content-Type-Options', 'Not Set')
        headers['Content-Security-Policy'] = response.headers.get('Content-Security-Policy', 'Not Set')
        headers['Strict-Transport-Security'] = response.headers.get('Strict-Transport-Security', 'Not Set')
    except Exception as e:
        return {"error": str(e)}
    return headers

# Web route to render the home page
@app.route('/')
def index():
    return render_template('index.html')

# Web route to handle vulnerability scan
@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    target_url = f"http://{target}" if not target.startswith('http') else target

    open_ports = scan_ports(target)
    headers = check_headers(target_url)

    return jsonify({"open_ports": open_ports, "headers": headers})

if __name__ == '__main__':
    app.run(debug=True)
