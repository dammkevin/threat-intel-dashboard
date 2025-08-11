import os
import requests

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def get_abuseipdb_iocs(min_score=90, country=None, limit=10):
    """
    Fetch IP IOCs from AbuseIPDB and return a normalized list of dicts:
    {type, value, score, country, source, tags, date}
    """
    if not API_KEY:
        print("AbuseIPDB API key not found. Set ABUSEIPDB_API_KEY in your environment or .env file.")
        return []

    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": min_score,
    }

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        print(f"AbuseIPDB request error: {e}")
        return []

    if response.status_code != 200:
        print(f"AbuseIPDB error {response.status_code}: {response.text}")
        return []

    data = response.json().get("data", [])
    results = []
    shown = 0

    for entry in data:
        if country and entry.get("countryCode", "").upper() != country.upper():
            continue

        results.append({
            "type": "ip",
            "value": entry.get("ipAddress"),
            "score": entry.get("abuseConfidenceScore"),
            "country": entry.get("countryCode"),
            "source": "AbuseIPDB",
            "tags": [],
            "date": None,
        })

        shown += 1
        if shown >= limit:
            break

    return results
