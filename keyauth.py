import socket
import ssl
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)


# Route to render the main index page
@app.route("/")
def index():
    return render_template("auth_check.html")


# Route to render the authentication checker page
@app.route("/auth_check")
def auth_check():
    return render_template("auth_check.html")


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
                    "strong" if key_exchange_strength >= 256 else
                    "moderate" if key_exchange_strength >= 128 else
                    "weak"
                )
                return {
                    "cipher": cipher_name,
                    "protocol_version": protocol_version,
                    "key_exchange_strength": key_exchange_strength,
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

    # Remove URL schema and path, if any
    hostname = server_url.replace("https://", "").replace("http://", "").split("/")[0]

    # Get encryption info for the user-specified server
    remote_server_info = get_encryption_info(hostname)

    # Get encryption info for the local network by connecting to Google
    local_network_info = get_encryption_info("www.google.com")

    return jsonify({
        "remote_server_info": remote_server_info,
        "local_network_info": local_network_info
    })


if __name__ == "__main__":
    app.run(debug=True)
