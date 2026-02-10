# BlackBox Lens (CLI) — Dependency Risk Scanner + Optional LLM Summary

**No HTML. No UI. Just a serious CLI.**

BlackBox Lens scans a dependency manifest, queries the **OSV** vulnerability database, computes an explainable **risk score (0–100)**, and (optionally) asks an LLM to write a concise, defensive summary.

## Install
```bash
pip install .
```

## Scan a manifest
```bash
blackbox-lens scan requirements.txt
```

Output:
- Prints a short heuristic summary to terminal
- Writes a full JSON report next to the file:
  - `requirements.txt.blackbox.json`

## Disable LLM (fully offline aside from OSV lookup)
```bash
blackbox-lens scan requirements.txt --no-llm
```

## LLM modes
Default is **Ollama** (local, no API key):
- start it: `ollama serve`
- set model (optional): `export OLLAMA_MODEL=llama3.1:8b`

Environment variables:
- `LLM_PROVIDER=ollama` (default) or `openai`
- `OLLAMA_URL` (default `http://localhost:11434`)
- `OLLAMA_MODEL` (default `llama3.1:8b`)
- `OPENAI_API_KEY` (if using `LLM_PROVIDER=openai`)
- `OPENAI_MODEL` (default `gpt-4.1-mini`)

## Explain an existing report
```bash
blackbox-lens explain requirements.txt.blackbox.json
```

## Docker
```bash
docker build -t blackbox-lens .
docker run --rm -v "$PWD:/work" -w /work blackbox-lens scan requirements.txt --no-llm
```

## License
MIT
