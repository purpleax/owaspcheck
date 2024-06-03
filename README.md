This script includes basic tests for some common vulnerabilities from the OWASP Top 10:

    Injection (SQL Injection)\
    Broken Authentication (Basic check for exposed admin interfaces)\
    Sensitive Data Exposure (Basic check for HTTPS)\
    XML External Entities (XXE) (Basic payload test)\
    Broken Access Control (Basic URL access check)\
    Security Misconfiguration (Basic directory listing check)\
    Cross-Site Scripting (XSS)\
    Insecure Deserialization (Basic payload test)\
    Using Components with Known Vulnerabilities (Outdated version check)\
    Insufficient Logging and Monitoring (Not easily scriptable, requires log analysis)

Save the script to a file, for example, owasp_scanner.py.

Install the requests library if you haven't already:

pip install requests

Run the script with the target server URL as an argument:

    python owasp_scanner.py http://your-target-server

Script Explanation:

    Menu: The script presents a menu with options to test for various OWASP Top 10 vulnerabilities.
    Target: The target server URL is specified via the command line.
    Tests: The script performs basic checks for the selected vulnerability.

Important Notes:

    This script provides only basic checks and is not a substitute for comprehensive security testing.
    Testing should be performed in a controlled environment with explicit permission.
    For more advanced and thorough testing, consider using dedicated tools like OWASP ZAP, Burp Suite, or commercial solutions.
