import pandas as pd

# Load the CSV file
data = pd.read_csv("trafego_rede.csv")

# Analyze the columns
print(data.info())

# 1. Count the countries of origin
country_counts = data['ClientCountry'].value_counts()

# Export the countries and their counts to a CSV file
country_counts.to_csv("requisicoes_por_pais.csv", header=["Quantity"], index_label="Country")
print("Exported: requisicoes_por_pais.csv")

# 2. Identify the most frequent requests
request_counts = data['ClientRequestURI'].value_counts(100)

# Export the most frequent requests to a CSV file
request_counts.to_csv("requisicoes_frequentes.csv", header=["Quantity"], index_label="RequestURI")
print("Exported: requisicoes_frequentes.csv")
