import os
import json
import requests
from typing import Any, Dict, List, Optional

def _trim(results: List[Dict[str, Any]], max_vulns: int = 25) -> List[Dict[str, Any]]:
    trimmed = []
    kept = 0
    for r in results:
        vulns = r.get("vulnerabilities", []) or []
        if not vulns:
            continue
        take = vulns[: max(0, max_vulns - kept)]
        kept += len(take)
        trimmed.append({
            "package": r.get("package"),
            "ecosystem": r.get("ecosystem"),
            "vuln_count": r.get("vuln_count", 0),
            "vulnerabilities": [{"id": v.get("id"), "summary": v.get("summary"), "aliases": v.get("aliases", [])} for v in take],
        })
        if kept >= max_vulns:
            break
    return trimmed

def generate_llm_summary(results: List[Dict[str, Any]], risk_score: int) -> str:
    provider = os.getenv("LLM_PROVIDER", "ollama").lower()
    if provider == "openai":
        return _openai(results, risk_score)
    return _ollama(results, risk_score)

def _ollama(results: List[Dict[str, Any]], risk_score: int) -> str:
    # Default: local Ollama (no API key). Assumes ollama is running on your machine.
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    payload_data = _trim(results)

    prompt = f"""You are a defensive security engineer.
Produce a concise report (max 12 bullets) based on dependency vulnerability findings.

Requirements:
- First line: one-sentence TL;DR including risk score {risk_score}/100
- Give: 3 Priority actions (numbered)
- Mention: any clusters (multiple issues in same package family) if visible
- Keep it practical, no fear-mongering, no exploit steps.

Findings (JSON):
{json.dumps(payload_data, indent=2)}
"""

    try:
        r = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        data = r.json()
        return (data.get("response") or "").strip() or "LLM returned an empty response."
    except Exception as e:
        return f"LLM unavailable (ollama). Run 'ollama serve' and pull a model. Details: {e}"

def _openai(results: List[Dict[str, Any]], risk_score: int) -> str:
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        return "LLM unavailable (openai). Set OPENAI_API_KEY or use LLM_PROVIDER=ollama."
    payload_data = _trim(results)
    instructions = (
        "You are a defensive security engineer. "
        f"Write a concise dependency risk summary with TL;DR including risk score {risk_score}/100, "
        "then 3 priority actions and key notes. No exploit instructions."
    )
    try:
        r = requests.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                "input": [
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": json.dumps(payload_data)},
                ],
            },
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        out = ""
        for item in data.get("output", []):
            for c in item.get("content", []):
                if c.get("type") == "output_text":
                    out += c.get("text", "")
        return out.strip() or "OpenAI returned an empty response."
    except Exception as e:
        return f"LLM unavailable (openai). Details: {e}"
