import csv
import io
import requests

CSV_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent.csv"


def get_urlhaus_iocs(limit=100, online_only=True):
    """
    Fetch recent malicious URLs from URLHaus (CSV) and return a normalized list:
    {type, value, score, country, source, tags, date}

    Notes:
    - URLHaus provides a CSV "recent" feed with columns like:
      id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
    - We treat:
        type   -> "url"
        value  -> url
        date   -> dateadded
        tags   -> combination of 'threat', 'url_status', and CSV 'tags' (if present)
    - score and country are not provided; set to None.
    - If online_only=True, we include only URLs where url_status is "online".
    """
    try:
        resp = requests.get(CSV_RECENT_URL, timeout=30)
    except requests.RequestException as e:
        print(f"URLHaus request error: {e}")
        return []

    if resp.status_code != 200:
        print(f"URLHaus error {resp.status_code}: {resp.text[:200]}")
        return []

    # The CSV has comment lines starting with '#', so we filter them out
    text = "\n".join(line for line in resp.text.splitlines() if not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(text))

    iocs = []
    for row in reader:
        # Defensive access; CSV header names may vary slightly, but these are the common ones
        url = (row.get("url") or "").strip()
        if not url:
            continue

        status = (row.get("url_status") or "").strip().lower()
        threat = (row.get("threat") or "").strip()
        dateadded = (row.get("dateadded") or "").strip()

        if online_only and status and status != "online":
            continue

        # CSV 'tags' is often a semicolon- or comma-separated list; normalize to a list
        raw_tags = (row.get("tags") or "").strip()
        split_tags = [t.strip() for t in raw_tags.replace(";", ",").split(",") if t.strip()]

        # Build our normalized IOC
        iocs.append({
            "type": "url",
            "value": url,
            "score": None,          # Not provided by URLHaus
            "country": None,        # Not provided by URLHaus
            "source": "URLHaus",
            "tags": list({t for t in ([threat, status] + split_tags) if t}),  # de-dup tags
            "date": dateadded,
        })

        if len(iocs) >= limit:
            break

    return iocs
