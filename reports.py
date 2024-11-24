from flask import Flask, render_template, jsonify, request
import datetime
import json
import os

app = Flask(__name__)

# File to store report history
REPORTS_FILE = 'reports.json'

# Function to load reports from file
def load_reports():
    if os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, 'r') as file:
            return json.load(file)
    return []


# Function to save a new report
def save_report(report):
    reports = load_reports()
    reports.append(report)
    with open(REPORTS_FILE, 'w') as file:
        json.dump(reports, file, indent=4)


# Route to render the report history page
@app.route("/reports")
def reports():
    loaded_reports = load_reports()
    # Sort reports by timestamp in descending order
    reports.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template("reports.html", reports=loaded_reports)


# Route to save a new report
@app.route("/save_report", methods=["POST"])
def save_report_route():
    report = request.json
    report['timestamp'] = datetime.datetime.now().isoformat()
    save_report(report)
    return jsonify({"message": "Report saved successfully!"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)
