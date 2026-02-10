import requests
from typing import Any, Dict, List

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

def query_osv_batch(packages: List[str], ecosystem: str) -> List[Dict[str, Any]]:
    # OSV querybatch: https://osv.dev/docs/ (batch query endpoint)
    queries = [{"package": {"name": name, "ecosystem": ecosystem}} for name in packages]
    r = requests.post(OSV_QUERYBATCH_URL, json={"queries": queries}, timeout=40)
    r.raise_for_status()
    data = r.json()

    results = []
    for name, item in zip(packages, data.get("results", []) or []):
        vulns = (item or {}).get("vulns", []) or []
        results.append({
            "package": name,
            "ecosystem": ecosystem,
            "vuln_count": len(vulns),
            "vulnerabilities": [
                {
                    "id": v.get("id"),
                    "summary": v.get("summary"),
                    "aliases": v.get("aliases", []),
                    "severity": v.get("severity", []),
                    "references": v.get("references", [])[:10],
                    "details": (v.get("details") or "")[:800],
                }
                for v in vulns
            ],
        })
    # If OSV returns fewer results (rare), fill missing
    if len(results) < len(packages):
        for name in packages[len(results):]:
            results.append({"package": name, "ecosystem": ecosystem, "vuln_count": 0, "vulnerabilities": []})
    return results
