
Internship-Developers-Hub

This is a Flask-based finance web application that allows users to register, log in, and manage a stock portfolio. The application provides features such as buying and selling stocks, checking stock quotes, viewing transaction history, and adding funds.

Features

User Authentication: Secure login and registration system.

Stock Transactions: Buy and sell stocks using real-time stock prices.

Portfolio Management: View current holdings and available cash balance.

Transaction History: Track previous stock transactions.

Multi-Factor Authentication (MFA) [New]: Added two-factor authentication using QR code and one-time passwords.

Technologies Used

Flask: Web framework for Python.

SQLite: Database to store user information and transactions.

CS50 Library: SQL integration for Flask.

Werkzeug Security: Secure password hashing.

Jinja2: Template rendering.

pyotp: One-time password (OTP) generation for MFA.

qrcode: QR code generation for MFA setup.

Installation

Prerequisites

Ensure you have Python installed along with the required dependencies:

pip install flask cs50 flask-session werkzeug pyotp qrcode

Setting Up the Database

Run the following command to create the necessary database schema:

sqlite3 finance.db < schema.sql

Running the Application

Execute the following command to start the Flask server:

python app1.py

Updates in app1.py

Implemented Multi-Factor Authentication (MFA):

Users can set up MFA using QR codes.

Login now requires an additional one-time password if MFA is enabled.

Added /setup-mfa route:

Generates a unique MFA secret for the user.

Provides a QR code for users to scan with an authenticator app.

Updated Login Workflow:

If a user has MFA enabled, they must enter an OTP along with their password.

Usage

Register a new account: Navigate to /register, enter a username and password.

Log in: Access /login and enter your credentials.

Enable MFA: After logging in, go to /setup-mfa to generate a QR code.

Buy/Sell Stocks: Use /buy and /sell to perform stock transactions.

View Portfolio: The homepage (/) displays current holdings.

Check Stock Prices: Use /quote to get stock prices.

Contributing

Feel free to fork this repository and submit pull requests for improvements.

License

This project is open-source and available under the MIT License.
