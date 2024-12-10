# VeriVuln

This project is a web-based vulnerability scanning tool that allows users to analyze security attributes of target systems, such as open ports, HTTP security headers, and encryption strength. It also generates downloadable reports for each scan.

## Features

- **User Authentication**: Secure registration and login functionality using Flask-Login and bcrypt.
- **Port Scanning**: Detects open ports within a specified range.
- **Encryption Strength Analysis**: Evaluates SSL/TLS key exchange strength for the target server.
- **HTTP Security Headers Check**: Identifies common HTTP security headers and their configurations.
- **Report Generation**: Generates detailed PDF reports for each scan.
- **Database Integration**: Stores user encrypted credentials and scan results using SQLAlchemy and MySQL.
- **CORS Support**: Enables cross-origin requests for specific routes.

## Requirements

The application requires the following dependencies:

- **Python 3.8+**
- **Flask** (Web framework)
- **SQLAlchemy** (ORM for database operations)
- **Flask-Login** (User session management)
- **Flask-WTF** (Form handling)
- **bcrypt** (Password hashing)
- **PyMySQL** (Database driver for MySQL)
- **cryptography** (Encryption and cryptographic operations)
- **requests** (HTTP requests)
- **reportlab** (PDF generation)
- **concurrent.futures** (Thread-based concurrency)
- **datetime** (Report logging)

## Installation for Running Locally

1. Clone the repository

2. Download any dependecies listed above, otherwise found on the '.py' files included

3. Run the 'vuln_scanner.py' file

## Non-Installation Gude for Running Live Server Build

1. Follow this link: https://verivuln.duckdns.org/

2. Enjoy the website running live on the Internet as intended

## Team Code Contributions

- <b>Jacob Chung</b>: Functionality for scanner (mostly encryption and authentication details), security header description and 'Advanced' information section, report history implementation with report database integration, general website structure, frontend design for scan page, 'About' page, and 'Report History' page
- <b>Mike Sadowski</b>: Security header backend code, port scanning functionality, Flask implementation, initial application launch, core features in early development 
- <b>Deni Cara</b>: Login functionality, database logging, user data encryption, frontend design for general page layout and login screen
- <b>Joshua Pokorzynski</b>: Live server implementation with functional online database and domain; transition from application to fully-online website
