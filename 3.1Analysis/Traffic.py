import pandas as pd

# Load the CSV file
data = pd.read_csv("trafego_rede.csv")

# Define thresholds for suspicious requests
MIN_BYTES = 100     # Minimum to be considered normal
MAX_BYTES = 15000   # Maximum to be considered normal

# Classify requests based on size
data['IsSizeSuspicious'] = (data['ClientRequestBytes'] < MIN_BYTES) | (data['ClientRequestBytes'] > MAX_BYTES)

# Filter only suspicious requests
suspicious_requests = data[data['IsSizeSuspicious']]

# Export to a CSV file
suspicious_requests.to_csv("suspicious_requests.csv", index=False)

# Display suspicious requests
print(suspicious_requests[['ClientIP', 'ClientRequestPath', 'ClientRequestBytes', 'IsSizeSuspicious']])
