import pandas as pd
import re

# Function to check if the path contains vulnerable patterns
def check_vulnerability(request_path):
    # Typical vulnerability patterns that can be found in URLs (e.g., login, commands)
    patterns = [
        r'login=.*',      # Login parameters
        r'password=.*',   # Password parameters
        r'admin.*',        # Paths containing 'admin'
        r'/eval\?.*',      # Code execution (typical example)
        r'\.\./\.\./',      # Relative directories (e.g., ../../)
        r'(<%.*exec.*>)',   # Code execution attempts (e.g., <%=Runtime.getRuntime().exec%>)
        r'<.*script.*>',    # Possible XSS attempts
        r'onerror.*',       # Possible XSS attempts in images
        r'[^a-zA-Z0-9\s/]', # Suspicious special characters
        r'/wp-admin/setup-config.php'  # Vulnerable WordPress path
    ]
    
    # Check if any pattern is found in the request_path
    for pattern in patterns:
        if re.search(pattern, request_path):
            return True
    return False

# Load the CSV file
data = pd.read_csv("trafego_rede.csv")

# Filter suspicious requests
data['IsVulnerable'] = data['ClientRequestPath'].apply(check_vulnerability)

# Filter records where vulnerabilities were detected
vulnerable_requests = data[data['IsVulnerable'] == True]

# Export the results to a new CSV
vulnerable_requests.to_csv('vulnerable.csv', index=False)

# Display vulnerable requests
print(vulnerable_requests[['ClientIP', 'ClientRequestHost', 'ClientRequestMethod', 'ClientRequestPath', 'EdgeStartTimestamp']])
