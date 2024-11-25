import pandas as pd
import re

# Function to identify the type of vulnerabilities in the request_path
def identify_vulnerabilities(request_path):
    # Define patterns and their respective categories
    patterns = {
        'Login Parameter': r'login=.*',
        'Password Parameter': r'password=.*',
        'Admin Path': r'admin.*',
        'Code Execution': r'/eval\?.*',
        'Directory Traversal': r'\.\./\.\./',
        'Code Injection': r'(<%.*exec.*>)',
        'XSS Script': r'<.*script.*>',
        'XSS Image onError': r'onerror.*',
        'Special Characters': r'[^a-zA-Z0-9\s/]',
        'WordPress Setup': r'/wp-admin/setup-config.php'
    }

    # Check which patterns are found
    vulnerabilities = []
    for vuln_type, pattern in patterns.items():
        if re.search(pattern, request_path):
            vulnerabilities.append(vuln_type)
    
    # Return the identified types of vulnerabilities
    return ', '.join(vulnerabilities) if vulnerabilities else 'None'

# Load the CSV file
data = pd.read_csv("vulnerable_requests.csv")

# Identify vulnerabilities in each ClientRequestPath
data['Vulnerabilities'] = data['ClientRequestPath'].apply(identify_vulnerabilities)

# Filter only the records with vulnerabilities
vulnerable_requests = data[data['Vulnerabilities'] != 'None']

# Sort the requests by type of vulnerability
vulnerable_requests_sorted = vulnerable_requests.sort_values(by='Vulnerabilities')

# Export the result to a new CSV file
vulnerable_requests_sorted.to_csv('vulnerable_grouped.csv', index=False)

# Display the first records grouped by vulnerabilities
print(vulnerable_requests_sorted[['ClientIP', 'ClientRequestHost', 'ClientRequestPath', 'Vulnerabilities']])
