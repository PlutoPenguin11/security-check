import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# Initialize Flask app and enable CORS
app = Flask(__name__)
CORS(app, resources={r"/scan": {"origins": "*"}})  # Adjust origins as needed

# Set up logging
logging.basicConfig(level=logging.INFO)


@app.route("/")
def index():
    return render_template("index.html")


# Checks for common security headers in the HTTP response.
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


@app.route("/scan", methods=["POST"])
# Handles the scan request. Performs HTTP header checks and port scanning.
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
    app.run(host="0.0.0.0", port=8000, debug=True, threaded=True)
