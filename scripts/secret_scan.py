#!/usr/bin/env python3
"""Conservative publication scan; prints locations, never matched values."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


TEXT_EXTENSIONS = {".html", ".css", ".js", ".json", ".md", ".py", ".txt", ".yaml", ".yml", ".xml", ".csv"}
ASSIGNMENT = re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret|private[_ -]?key|authorization|bearer)\b\s*[:=]\s*['\"]?(?!YOUR|PLACEHOLDER|UNKNOWN|NONE|REDACTED|\[)[A-Za-z0-9_./+=-]{12,}")
HIGH_RISK = [
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(?:ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}\b")),
    ("cloud_secret", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("windows_home_path", re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\/\s]+")),
    ("linux_home_path", re.compile(r"(?i)\b/home/[^\s/]+")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def allowed_public_emails(root: Path) -> set[str]:
    data_path = root / "data" / "portfolio.json"
    try:
        data = json.loads(data_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return set()
    email = data.get("owner_email")
    return {str(email).lower()} if email else set()


def scan(root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    allowed_emails = allowed_public_emails(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "secret_scan.py" or path.suffix.lower() not in TEXT_EXTENSIONS or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if ASSIGNMENT.search(line):
                findings.append({"type": "credential_assignment", "file": str(path.relative_to(root)), "line": line_number})
            for name, pattern in HIGH_RISK:
                if pattern.search(line):
                    # Placeholders and policy examples are intentionally not
                    # printed; only the location is reported.
                    if name == "email_address" and any(match.lower() in allowed_emails for match in pattern.findall(line)):
                        continue
                    findings.append({"type": name, "file": str(path.relative_to(root)), "line": line_number})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    findings = scan(args.root.resolve())
    print(json.dumps({"status": "CLEAN" if not findings else "PUBLICATION_BLOCKED_SECRET_REVIEW_REQUIRED", "findings": findings}, indent=2))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
