import re
import csv
from datetime import datetime
import pandas as pd

# Security policies to prevent vulnerabilities
POLICIES = {
    "sql_injection": {
        "regex": r"(UNION.*SELECT|admin['\"].*--|SELECT\s.*FROM\s.*|;.*DROP\s+TABLE|<.*script.*>)",
        "description": "Detects SQL Injection patterns, including basic XSS payloads.",
        "action": "block"
    },
    "admin_page_access": {
        "regex": r"(/wp-admin|/admin|/login\.jsp)",
        "description": "Restricts access to admin pages.",
        "action": "block"
    },
    "el_injection": {
        "regex": r"(\$\{.*?\})",
        "description": "Detects EL Injection payloads.",
        "action": "block"
    },
    "rce": {
        "regex": r"(shell\.php|cmd=|;.*&&.*|<%.*exec.*>)",
        "description": "Detects Remote Code Execution attempts via URL or commands.",
        "action": "block"
    },
    "credentials_in_url": {
        "regex": r"(user=.+&password=.+|auth=.*)",
        "description": "Detects credentials passed in URL.",
        "action": "block"
    },
    "sensitive_files": {
        "regex": r"(/robots\.txt|/phpinfo\.php|/config\.yml|/wp-admin/setup-config.php)",
        "description": "Blocks access to sensitive files.",
        "action": "block"
    },
    "lfi_traversal": {
        "regex": r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|/eval\?.*)",
        "description": "Detects Local File Inclusion and Directory Traversal attempts.",
        "action": "block"
    },
    "exposed_git": {
        "regex": r"(/\.git/)",
        "description": "Blocks access to .git directories.",
        "action": "block"
    },
    "null_byte": {
        "regex": r"(%00)",
        "description": "Detects Null Byte Injection.",
        "action": "block"
    },
    "dos": {
        "threshold": 100,
        "description": "Limits excessive request rates.",
        "action": "rate_limit"
    },
    "xss": {
        "regex": r"(<script>.*</script>|onerror=|alert\(['\"].*['\"]\))",
        "description": "Detects XSS payloads.",
        "action": "block"
    }
}


def check_security_policies(request_path, payload, policies, request_count, ip):
    """Checks security policies to detect malicious patterns."""
    suspicious_entries = []
    combined_payload = request_path + payload

    for policy_name, policy in policies.items():
        # Check for matches using regex
        if "regex" in policy and re.search(policy["regex"], combined_payload, re.IGNORECASE):
            suspicious_entries.append({
                "policy": policy_name,
                "reason": policy["description"],
                "action": policy["action"]
            })
        
        # DoS check - moved here to ensure request_count is accessed correctly
        elif policy_name == "dos" and request_count.get(ip, 0) > policy["threshold"]:
            suspicious_entries.append({
                "policy": policy_name,
                "reason": "DoS Pattern Detected",
                "action": "BLOCKED"
            })

    return suspicious_entries

def analyze_traffic(data, policies):
    """Analyzes traffic for suspicious patterns based on security policies."""
    suspicious_traffic = []
    request_count = {}

    for _, entry in data.iterrows():
        ip = entry.get("ClientIP")
        if not ip:
            continue

        request_path = entry.get("ClientRequestPath", "")
        payload = entry.get("ClientRequestReferer", "")

        # Count requests per IP
        request_count[ip] = request_count.get(ip, 0) + 1

        # Check security policies for each request
        suspicious_entries = check_security_policies(request_path, payload, policies, request_count, ip)
        if suspicious_entries:
            for entry in suspicious_entries:
                suspicious_traffic.append({
                    "ip": ip,
                    "reason": entry["reason"],
                    "action": entry["action"]
                })
    
    return suspicious_traffic

def save_suspicious_traffic(suspicious_traffic):
    """Saves suspicious traffic results to a CSV file."""
    if suspicious_traffic:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("suspicious_traffic_log.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "IP", "Reason", "Action"])
            for item in suspicious_traffic:
                writer.writerow([timestamp, item["ip"], item["reason"], item["action"]])

def main():
    """Main function to load, analyze, and save traffic data."""
    # Load CSV data(put your csv name)
    data = pd.read_csv("traffic_log.csv")

    suspicious_traffic = analyze_traffic(data, POLICIES)

    save_suspicious_traffic(suspicious_traffic)

if __name__ == "__main__":
    main()
