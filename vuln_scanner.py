import socket

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


def check_headers(target_url):
    headers = {}

    # Temporary, replace when ready

    try:
        response = requests.get(target_url, timeout=5, verify=False)
        headers["X-Frame-Options"] = response.headers.get("X-Frame-Options", "Not Set")
        headers["X-Content-Type-Options"] = response.headers.get(
            "X-Content-Type-Options", "Not Set"
        )
        headers["Content-Security-Policy"] = response.headers.get(
            "Content-Security-Policy", "Not Set"
        )
        headers["Strict-Transport-Security"] = response.headers.get(
            "Strict-Transport-Security", "Not Set"
        )
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    return headers


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"].strip()
    port_start = int(request.form.get("port_start", 1))
    port_end = int(request.form.get("port_end", 1024))

    print(f"Scanning target: {target} from port {port_start} to {port_end}")

    headers = check_headers(target)
    open_ports = []

    target_host = target.replace("http://", "").replace("https://", "")

    for port in range(port_start, port_end + 1):
        print(f"Scanning port: {port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target_host, port))
                if result == 0:
                    open_ports.append(port)
        except socket.gaierror as e:
            print(f"Socket error for {target_host} on port {port}: {e}")

    print(f"Open ports: {open_ports}")
    return jsonify({"headers": headers, "open_ports": open_ports})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
