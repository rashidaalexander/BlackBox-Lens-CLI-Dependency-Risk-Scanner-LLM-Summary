import json
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass(frozen=True)
class ParsedInput:
    kind: str
    ecosystem: str
    packages: List[str]

def parse_requirements_txt(text: str) -> List[str]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip()
        if name:
            # strip extras like pkg[extra]
            name = name.split("[", 1)[0].strip()
            if name:
                pkgs.append(name)
    return sorted(set(pkgs))

def parse_package_lock_json(text: str) -> List[str]:
    data = json.loads(text)
    deps = data.get("dependencies", {}) or {}
    return sorted(set(deps.keys()))

def parse_pyproject_toml(text: str) -> List[str]:
    # Best-effort parse: pull dependency-like strings.
    pkgs = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("["):
            continue
        s = s.strip('"').strip("'")
        if any(op in s for op in ["<", ">", "=", "~"]):
            name = re.split(r"[<>=!~]", s, maxsplit=1)[0].strip()
            if name and " " not in name and len(name) <= 80:
                name = name.split("[", 1)[0].strip()
                if name:
                    pkgs.add(name)
    return sorted(pkgs)

def detect_and_parse(filename: str, raw: bytes) -> ParsedInput:
    text = raw.decode("utf-8", errors="replace")
    fn = filename.lower()

    if fn.endswith("requirements.txt"):
        return ParsedInput(kind="requirements.txt", ecosystem="PyPI", packages=parse_requirements_txt(text))
    if fn.endswith("package-lock.json"):
        return ParsedInput(kind="package-lock.json", ecosystem="npm", packages=parse_package_lock_json(text))
    if fn.endswith("pyproject.toml"):
        return ParsedInput(kind="pyproject.toml", ecosystem="PyPI", packages=parse_pyproject_toml(text))

    raise ValueError("Unsupported file type. Use requirements.txt, pyproject.toml, or package-lock.json.")
