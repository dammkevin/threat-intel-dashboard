import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def get_blacklist(limit=10):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }

    params = {
        'confidenceMinimum': 90
    }

    response = requests.get(BASE_URL, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()['data']
        for entry in data[:limit]:
            print(f"{entry['ipAddress']} | Score: {entry['abuseConfidenceScore']} | Country: {entry['countryCode']}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
