import requests
import os
import argparse

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist"


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="AbuseIPDB IOC Fetcher with filtering options")
    parser.add_argument("--country", help="Filter results by country code (e.g. US, CN)")
    parser.add_argument("--min-score", type=int, default=90, help="Minimum abuse confidence score (25–100)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of results to display")
    return parser.parse_args()

# Fetch and display filtered IOCs
def get_blacklist(min_score=90, country=None, limit=10):
    if not API_KEY:
        print("API key not found. Set it using the ABUSEIPDB_API_KEY environment variable.")
        return

    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }

    params = {
        'confidenceMinimum': min_score
    }

    response = requests.get(BASE_URL, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get('data', [])
        shown = 0
        for entry in data:
            if country and entry['countryCode'].upper() != country.upper():
                continue
            print(f"{entry['ipAddress']} | Score: {entry['abuseConfidenceScore']} | Country: {entry['countryCode']}")
            shown += 1
            if shown >= limit:
                break
    else:
        print(f"Error {response.status_code}: {response.text}")


# Entry point
if __name__ == "__main__":
    args = parse_args()
    get_blacklist(
        min_score=args.min_score,
        country=args.country,
        limit=args.limit
    )
