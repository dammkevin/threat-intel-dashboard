import argparse
import json
import csv

from ioc_sources.abuseipdb import get_abuseipdb_iocs
from ioc_sources.alienvault_otx import get_otx_iocs


CANONICAL_TYPE_MAP = {
    # OTX might return "IPv4", "domain", "URL", "MD5", "SHA256"
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "MD5": "hash",
    "SHA1": "hash",
    "SHA256": "hash",
}

def parse_args():
    parser = argparse.ArgumentParser(description="Threat Intel CLI Aggregator")
    parser.add_argument("--sources",
                        default="abuseipdb,otx",
                        help="Comma-separated list of sources to pull (abuseipdb, otx)")
    parser.add_argument("--country", help="Filter by country code (applies to sources that include country)")
    parser.add_argument("--min-score", type=int, default=90, help="Minimum abuse score (25–100, AbuseIPDB only)")
    parser.add_argument("--type", help="Filter by IOC type (ip, domain, url, hash)")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of results to display (after filtering/dedup)")
    parser.add_argument("--save-to", choices=["json", "csv"], help="Export results to a JSON or CSV file")
    return parser.parse_args()

def canonical_type(t):
    if not t:
        return None
    return CANONICAL_TYPE_MAP.get(t, t.lower())

def export_results(iocs, format="json"):
    if format == "json":
        with open("ioc_results.json", "w") as f:
            json.dump(iocs, f, indent=2)
        print("Results saved to ioc_results.json")
    elif format == "csv":
        with open("ioc_results.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "value", "score", "country", "source", "tags", "date"])
            writer.writeheader()
            writer.writerows(iocs)
        print("Results saved to ioc_results.csv")

def fetch_from_sources(sources, min_score, country):
    all_iocs = []

    if "abuseipdb" in sources:
        all_iocs.extend(
            get_abuseipdb_iocs(min_score=min_score, country=country, limit=10_000)  # fetch plenty; we’ll limit later
        )

    if "otx" in sources:
        all_iocs.extend(
            get_otx_iocs(limit=10_000)
        )

    # Normalize types to canonical set
    for i in all_iocs:
        i["type"] = canonical_type(i.get("type"))

    return all_iocs

def dedupe_iocs(iocs):
    seen = set()
    deduped = []
    for i in iocs:
        key = f"{i.get('type')}:{i.get('value')}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(i)
    return deduped

def apply_filters(iocs, ioc_type=None, country=None):
    out = []
    for i in iocs:
        if ioc_type and i.get("type") != ioc_type:
            continue
        if country and i.get("country") and i.get("country").upper() != country.upper():
            continue
        out.append(i)
    return out

if __name__ == "__main__":
    args = parse_args()

    requested_sources = set(s.strip().lower() for s in args.sources.split(",") if s.strip())

    iocs = fetch_from_sources(
        sources=requested_sources,
        min_score=args.min_score,
        country=args.country
    )

    iocs = dedupe_iocs(iocs)
    iocs = apply_filters(iocs, ioc_type=args.type, country=args.country)

    # Final display limit (after dedup and filters)
    iocs = iocs[:args.limit]

    for ioc in iocs:
        print(f"{ioc['value']} | Type: {ioc['type']} | Score: {ioc['score']} | Country: {ioc['country']} | Source: {ioc['source']}")

    if args.save_to:
        export_results(iocs, args.save_to)
