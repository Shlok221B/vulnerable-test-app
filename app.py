#!/usr/bin/env python3
"""
Vulnerable Web Application - FOR TESTING PURPOSES ONLY
This application contains intentional security vulnerabilities for demonstration.
DO NOT USE IN PRODUCTION!
"""

import os
import sqlite3
import subprocess
import pickle
from flask import Flask, request, render_template_string, session, redirect, url_for
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"  # Vulnerability: Hardcoded secret

# Vulnerability: SQL Injection
def authenticate_user(username, password):
    """Authenticate user with vulnerable SQL query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection - user input directly concatenated
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# Vulnerability: Command Injection
@app.route('/ping', methods=['POST'])
def ping_host():
    """Ping a host - vulnerable to command injection."""
    host = request.form.get('host', '')
    
    # VULNERABLE: Command injection - user input directly used in system command
    try:
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
        return f"<pre>{result}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

# Vulnerability: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    """Search functionality with XSS vulnerability."""
    query = request.args.get('q', '')
    
    # VULNERABLE: XSS - user input rendered without escaping
    template = f"""
    <h2>Search Results for: {query}</h2>
    <p>No results found for your search.</p>
    """
    return render_template_string(template)

# Vulnerability: Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    """Deserialize user data - vulnerable to code execution."""
    data = request.form.get('data', '')
    
    try:
        # VULNERABLE: Insecure deserialization
        obj = pickle.loads(data.encode())
        return f"Deserialized: {obj}"
    except Exception as e:
        return f"Error: {str(e)}"

# Vulnerability: Path Traversal
@app.route('/file')
def read_file():
    """Read file contents - vulnerable to path traversal."""
    filename = request.args.get('name', '')
    
    try:
        # VULNERABLE: Path traversal - no input validation
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

# Vulnerability: Weak Password Hashing
def hash_password(password):
    """Hash password using weak algorithm."""
    # VULNERABLE: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability: Information Disclosure
@app.route('/debug')
def debug_info():
    """Show debug information."""
    # VULNERABLE: Information disclosure
    env_vars = dict(os.environ)
    return f"<pre>Environment Variables:\n{env_vars}</pre>"

# Vulnerability: Insecure Direct Object Reference
@app.route('/user/<user_id>')
def get_user(user_id):
    """Get user information without authorization check."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: No authorization check
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return f"User: {user[0]}, Email: {user[1]}"
    return "User not found"

# Vulnerability: Server-Side Request Forgery (SSRF)
@app.route('/fetch', methods=['POST'])
def fetch_url():
    """Fetch content from URL - vulnerable to SSRF."""
    url = request.form.get('url', '')
    
    try:
        # VULNERABLE: SSRF - no URL validation
        import urllib.request
        response = urllib.request.urlopen(url)
        content = response.read().decode()
        return f"<pre>{content[:1000]}</pre>"  # Limit output
    except Exception as e:
        return f"Error: {str(e)}"

# Vulnerability: XML External Entity (XXE)
@app.route('/xml', methods=['POST'])
def parse_xml():
    """Parse XML data - vulnerable to XXE."""
    xml_data = request.form.get('xml', '')
    
    try:
        # VULNERABLE: XXE - XML parser allows external entities
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_data)
        return f"Parsed XML: {root.tag}"
    except Exception as e:
        return f"Error: {str(e)}"

# Initialize database with vulnerable setup
def init_db():
    """Initialize database with sample data."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    
    # Insert sample users with weak passwords
    users = [
        (1, 'admin', hash_password('admin123'), 'admin@example.com'),
        (2, 'user', hash_password('password'), 'user@example.com'),
        (3, 'test', hash_password('123456'), 'test@example.com')
    ]
    
    cursor.executemany('INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?)', users)
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Main page with links to vulnerable endpoints."""
    return """
    <h1>Vulnerable Test Application</h1>
    <p><strong>WARNING: This application contains intentional vulnerabilities for testing purposes only!</strong></p>
    
    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/search?q=<script>alert('XSS')</script>">XSS Test</a></li>
        <li><a href="/file?name=../../../etc/passwd">Path Traversal Test</a></li>
        <li><a href="/user/1">Direct Object Reference</a></li>
        <li><a href="/debug">Information Disclosure</a></li>
    </ul>
    
    <h2>POST Endpoints:</h2>
    <form method="post" action="/ping">
        <label>Ping Host:</label>
        <input type="text" name="host" value="127.0.0.1; cat /etc/passwd">
        <button type="submit">Ping</button>
    </form>
    """

if __name__ == '__main__':
    init_db()
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)