from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import json
import time

@dataclass
class Report:
    tool: str
    version: str
    created_at: str
    input_file: str
    kind: str
    ecosystem: str
    packages_scanned: int
    total_vulnerabilities: int
    risk_score: int
    results: List[Dict[str, Any]]
    heuristic_summary: str
    llm_summary: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

def compute_risk_score(results: List[Dict[str, Any]]) -> int:
    # Explainable scoring (0..100)
    score = 0
    for r in results:
        vc = int(r.get("vuln_count", 0) or 0)
        score += vc * 8
        for v in (r.get("vulnerabilities", []) or []):
            if v.get("severity"):
                score += 3
    return min(100, score)

def heuristic_summary(results: List[Dict[str, Any]], risk_score: int) -> str:
    total = sum(int(r.get("vuln_count", 0) or 0) for r in results)
    affected = [r["package"] for r in results if int(r.get("vuln_count", 0) or 0) > 0]
    if total == 0:
        return f"Risk {risk_score}/100. No known OSV vulnerabilities found. Keep deps updated and re-scan."
    top = affected[:8]
    more = max(0, len(affected) - len(top))
    pkg_list = ", ".join(top) + (f" (+{more} more)" if more else "")
    if risk_score >= 70:
        tone = "High risk — prioritize patching now."
    elif risk_score >= 40:
        tone = "Moderate risk — schedule upgrades soon."
    else:
        tone = "Low-to-moderate risk — address during maintenance."
    return f"Risk {risk_score}/100. Found {total} vulnerabilities affecting: {pkg_list}. {tone}"

def build_report(*, version: str, input_file: str, kind: str, ecosystem: str, results: List[Dict[str, Any]], llm_summary: str | None = None) -> Report:
    score = compute_risk_score(results)
    total = sum(int(r.get('vuln_count', 0) or 0) for r in results)
    heur = heuristic_summary(results, score)
    # ISO-ish timestamp without timezone (good enough for CLI)
    created = time.strftime("%Y-%m-%dT%H:%M:%S")
    return Report(
        tool="blackbox-lens",
        version=version,
        created_at=created,
        input_file=input_file,
        kind=kind,
        ecosystem=ecosystem,
        packages_scanned=len(results),
        total_vulnerabilities=total,
        risk_score=score,
        results=results,
        heuristic_summary=heur,
        llm_summary=llm_summary,
    )
