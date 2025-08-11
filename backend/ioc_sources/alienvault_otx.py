import os
import requests

API_KEY = os.getenv("ALIENVAULT_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/export"


def get_otx_iocs(limit=100):
    """
    Fetch indicators from AlienVault OTX export (CSV) and return a normalized list:
    {type, value, score, country, source, tags, date}
    Note: OTX export does not include numeric scores or country info.
    """
    if not API_KEY:
        print("AlienVault OTX API key not found. Set ALIENVAULT_API_KEY in your environment or .env file.")
        return []

    headers = {
        "X-OTX-API-KEY": API_KEY,
        "Accept": "text/csv",
    }

    try:
        response = requests.get(BASE_URL, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"OTX request error: {e}")
        return []

    if response.status_code != 200:
        print(f"OTX error {response.status_code}: {response.text}")
        return []

    iocs = []
    lines = response.text.strip().splitlines()

    for line in lines:
        if not line or line.startswith("#"):
            continue

        parts = line.split(",")
        if len(parts) < 4:
            continue

        indicator_type = parts[0].strip()
        indicator_value = parts[1].strip()
        date = parts[2].strip()

        iocs.append({
            "type": indicator_type,   # e.g., "IPv4", "domain", "URL", "MD5", "SHA256"
            "value": indicator_value,
            "score": None,            # Not provided by this feed
            "country": None,          # Not provided by this feed
            "source": "AlienVault OTX",
            "tags": [],
            "date": date,
        })

        if len(iocs) >= limit:
            break

    return iocs
