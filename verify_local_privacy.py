"""Local source-copy checks; prints locations/categories, never matched values."""
import ast
import argparse
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
DENIED_PARTS = {"data", ".git", "__pycache__", "backups", "runs", "plans", "node_modules"}
DENIED_SUFFIXES = {".pyc", ".pyo", ".zip", ".whl", ".gz", ".tar", ".key", ".pem",
                   ".p12", ".pfx", ".keystore", ".so", ".dylib", ".log", ".bak", ".backup"}
PATTERNS = {
    "personal-home-path": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+"),
    "email-address": re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    "URL-credentials": re.compile(r"https?://[^\s/]+@"),
    "URL-secret-query": re.compile(r"(?i)[?&](?:api_key|apikey|access_token|password|secret)=[^\s\"']+"),
}

def inspect(root, forbidden_terms=()):
    issues = []
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            issues.append({"file": str(relative), "category": "symlink"})
            continue
        if not path.is_file():
            if set(relative.parts) & DENIED_PARTS:
                issues.append({"file": str(relative), "category": "runtime-directory"})
            continue
        files.append(str(relative))
        if (set(relative.parts) & DENIED_PARTS or path.suffix.lower() in DENIED_SUFFIXES or
                path.name == ".DS_Store" or path.name.startswith(".env") or
                any(part.startswith((".venv", ".private")) for part in relative.parts) or
                path.name.lower().startswith("wallet") or "wallet" in path.name.lower() and path.suffix == ".json"):
            issues.append({"file": str(relative), "category": "private-or-generated-artifact"})
            continue
        try:
            text = path.read_text()
        except (UnicodeError, OSError):
            issues.append({"file": str(relative), "category": "non-text-or-unreadable"})
            continue
        for category, pattern in PATTERNS.items():
            if pattern.search(text):
                issues.append({"file": str(relative), "category": category})
        if any(term.casefold() in text.casefold() for term in forbidden_terms if term):
            issues.append({"file": str(relative), "category": "forbidden-personal-term"})
        username = os.environ.get("USER", "")
        if len(username) > 4 and username.lower() in text.lower():
            issues.append({"file": str(relative), "category": "local-account-name"})
        if path.suffix == ".py":
            try:
                ast.parse(text, filename=str(relative))
            except SyntaxError:
                issues.append({"file": str(relative), "category": "invalid-Python-source"})
    return {"files_checked": len(files), "issues": issues, "passed": not issues,
            "network": False, "upload": False, "operator_wallets_opened": False,
            "note": "Finite privacy checks; use the included Gitleaks configuration for secret detection."}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid-text", action="append", default=[])
    args = parser.parse_args()
    result = inspect(ROOT, args.forbid_text)
    print(json.dumps(result, indent=2))
    sys.exit(int(not result["passed"]))
