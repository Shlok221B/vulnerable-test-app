# Vulnerable Test Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for testing purposes only!**

## Overview

This sample application demonstrates various common security vulnerabilities that can be detected by Checkmarx scans. It includes vulnerabilities in multiple languages:

- **Python (Flask)**: `app.py`
- **Java**: `java_vulnerable.java`

## Vulnerabilities Included

### Python Vulnerabilities (app.py)
1. **SQL Injection** - Direct string concatenation in SQL queries
2. **Command Injection** - Unsafe use of shell commands
3. **Cross-Site Scripting (XSS)** - Unescaped user input in templates
4. **Insecure Deserialization** - Unsafe pickle usage
5. **Path Traversal** - No input validation for file paths
6. **Weak Password Hashing** - Using MD5 for passwords
7. **Information Disclosure** - Exposing environment variables
8. **Insecure Direct Object Reference** - No authorization checks
9. **Server-Side Request Forgery (SSRF)** - Unrestricted URL fetching
10. **XML External Entity (XXE)** - Unsafe XML parsing
11. **Hardcoded Secrets** - Secret key in source code

### Java Vulnerabilities (java_vulnerable.java)
1. **SQL Injection** - String concatenation in SQL
2. **Command Injection** - Runtime.exec() with user input
3. **Path Traversal** - File operations without validation
4. **Weak Cryptography** - MD5 password hashing
5. **Insecure Deserialization** - ObjectInputStream with untrusted data
6. **XXE** - XML parser allowing external entities
7. **Insecure Random** - Predictable random number generation
8. **Information Disclosure** - Exposing system properties
9. **LDAP Injection** - Unsafe LDAP filter construction
10. **Reflection Abuse** - Unrestricted class instantiation
11. **Hardcoded Credentials** - Passwords and API keys in code

## Usage for Testing

1. Upload this code to a GitHub repository
2. Configure the Checkmarx CI scanner to scan this repository
3. The scanner should detect multiple vulnerabilities across different categories

## Security Note

**DO NOT deploy this application in any production environment!** These vulnerabilities are intentionally created for security testing and demonstration purposes only.

## License

This code is provided for educational and testing purposes only.