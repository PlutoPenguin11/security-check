import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("api_test.html")


def check_api_type_and_headers(target_url):
    api_info = {"type": "Unknown", "headers": {}, "warnings": []}

    try:
        # Send a GET request to the target URL
        response = requests.get(target_url, timeout=5, verify=False)
        
        # Basic checks for API type
        if "application/json" in response.headers.get("Content-Type", ""):
            if "/graphql" in target_url:
                api_info["type"] = "GraphQL"
            else:
                api_info["type"] = "REST"
        
        # Collect specific headers
        api_info["headers"]["Authorization"] = response.headers.get("Authorization", "Not Set")
        api_info["headers"]["Access-Control-Allow-Origin"] = response.headers.get("Access-Control-Allow-Origin", "Not Set")
        api_info["headers"]["Content-Security-Policy"] = response.headers.get("Content-Security-Policy", "Not Set")
        
        # Evaluate security warnings
        if api_info["headers"]["Access-Control-Allow-Origin"] == "*":
            api_info["warnings"].append("Permissive CORS policy: API allows access from any origin.")
        
        if api_info["headers"]["Authorization"] == "Not Set":
            api_info["warnings"].append("No authorization required: API may be open to unauthorized access.")
        
        if api_info["headers"]["Content-Security-Policy"] == "Not Set":
            api_info["warnings"].append("Missing Content Security Policy: API might be vulnerable to XSS attacks.")

    except requests.exceptions.RequestException as e:
        api_info["error"] = f"Request failed: {e}"

    return api_info


@app.route("/scan_api", methods=["POST"])
def scan_api():
    target = request.form["target"].strip()

    print(f"Scanning API: {target}")

    # Check API type and security headers
    api_info = check_api_type_and_headers(target)
    return jsonify(api_info)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
