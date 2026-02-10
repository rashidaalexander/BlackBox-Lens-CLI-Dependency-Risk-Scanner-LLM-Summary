import json
import pathlib
from typing import Optional

import typer

from . import __version__
from .parsers import detect_and_parse
from .osv_client import query_osv_batch
from .report import build_report, compute_risk_score
from .llm import generate_llm_summary

app = typer.Typer(add_completion=False, help="BlackBox Lens — dependency risk scanner with optional LLM summaries.")

@app.command()
def scan(
    file: pathlib.Path = typer.Argument(..., exists=True, readable=True, help="Path to requirements.txt / pyproject.toml / package-lock.json"),
    out: Optional[pathlib.Path] = typer.Option(None, "--out", "-o", help="Write JSON report to this path (default: <input>.blackbox.json)"),
    llm: bool = typer.Option(True, "--llm/--no-llm", help="Enable LLM summary (Ollama default, OpenAI optional)"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output"),
):
    raw = file.read_bytes()
    parsed = detect_and_parse(file.name, raw)

    packages = parsed.packages
    if not packages:
        raise typer.BadParameter("No packages detected.")

    results = query_osv_batch(packages, ecosystem=parsed.ecosystem)
    score = compute_risk_score(results)

    llm_summary = None
    if llm:
        llm_summary = generate_llm_summary(results, score)

    report = build_report(
        version=__version__,
        input_file=str(file),
        kind=parsed.kind,
        ecosystem=parsed.ecosystem,
        results=results,
        llm_summary=llm_summary,
    )

    if out is None:
        out = file.with_suffix(file.suffix + ".blackbox.json")

    out.write_text(report.to_json() if pretty else json.dumps(json.loads(report.to_json())), encoding="utf-8")

    # Console output: always show a short summary + where the report went
    typer.echo(report.heuristic_summary)
    if llm and report.llm_summary:
        typer.echo("\nLLM summary:\n" + report.llm_summary.strip())
    typer.echo(f"\nReport written to: {out}")

@app.command()
def explain(report: pathlib.Path = typer.Argument(..., exists=True, readable=True, help="A previously generated .blackbox.json report")):
    data = json.loads(report.read_text(encoding="utf-8"))
    typer.echo(data.get("heuristic_summary", "No summary found."))
    llm_sum = data.get("llm_summary")
    if llm_sum:
        typer.echo("\nLLM summary:\n" + str(llm_sum).strip())

def main():
    app()

if __name__ == "__main__":
    main()
