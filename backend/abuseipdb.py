import requests
import os
import argparse
import json
import csv

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist"


# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="AbuseIPDB IOC Fetcher with filtering and export options")
    parser.add_argument("--country", help="Filter results by country code (e.g. US, CN)")
    parser.add_argument("--min-score", type=int, default=90, help="Minimum abuse confidence score (25–100)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of results to display")
    parser.add_argument("--save-to", choices=["json", "csv"], help="Export results to a JSON or CSV file")
    return parser.parse_args()

# Fetch and optionally export IOCs
def get_blacklist(min_score=90, country=None, limit=10, save_to=None):
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
        results = []
        shown = 0

        for entry in data:
            if country and entry['countryCode'].upper() != country.upper():
                continue

            result = {
                'ip': entry['ipAddress'],
                'score': entry['abuseConfidenceScore'],
                'country': entry['countryCode']
            }

            # Print to console
            print(f"{result['ip']} | Score: {result['score']} | Country: {result['country']}")
            results.append(result)

            shown += 1
            if shown >= limit:
                break

        # Export to file if requested
        if save_to == "json":
            with open("ioc_results.json", "w") as f:
                json.dump(results, f, indent=2)
            print("Results saved to ioc_results.json")

        elif save_to == "csv":
            with open("ioc_results.csv", "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "score", "country"])
                writer.writeheader()
                writer.writerows(results)
            print("Results saved to ioc_results.csv")

    else:
        print(f"Error {response.status_code}: {response.text}")


# Entry point
if __name__ == "__main__":
    args = parse_args()
    get_blacklist(
        min_score=args.min_score,
        country=args.country,
        limit=args.limit,
        save_to=args.save_to
    )
