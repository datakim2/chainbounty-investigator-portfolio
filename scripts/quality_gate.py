#!/usr/bin/env python3
"""Deterministic factual and publication gate for the sanitized portfolio."""

from __future__ import annotations

import json
import re
from pathlib import Path


EXPECTED_ATTACK_TYPES = {
    "Movie Token": "TOKEN_LOGIC_PRICE_MANIPULATION_EXPLOIT",
    "Truebit": "INTEGER_OVERFLOW_TOKEN_MINTING_EXPLOIT",
    "GnosisPay": "SIGNATURE_VERIFICATION_AUTHORIZATION_BYPASS",
}
EXPECTED_DISPLAY_LABELS = {
    "Movie Token": "Token Logic / Price Manipulation Exploit",
    "Truebit": "Integer Overflow / Token Minting Exploit",
    "GnosisPay": "Signature Verification / Authorization Bypass",
}
PLACEHOLDER_WORD = "YOUR"
PLACEHOLDERS = (f"[{PLACEHOLDER_WORD} NAME]", f"[{PLACEHOLDER_WORD} PUBLIC EMAIL]", f"[{PLACEHOLDER_WORD} X PROFILE]")
LEGACY_SOLANA_ENUM = "SOLANA" + "_VALIDATOR_NOT_CONFIGURED"
LEGACY_BRIDGE_ENUM = "BRIDGE" + "_EXPLOIT"
LEGACY_BRIDGE_LABEL = "Bridge" + " Exploit"


def normalize_label(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    data_path = root / "data" / "portfolio.json"
    data = json.loads(data_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    blockers: list[str] = []
    cases = {case.get("project"): case for case in data.get("cases") or []}

    for project, expected_type in EXPECTED_ATTACK_TYPES.items():
        case = cases.get(project)
        if not case:
            errors.append(f"missing case: {project}")
            continue
        if case.get("attack_type") != expected_type:
            errors.append(f"wrong attack type: {project}")
        if normalize_label(case.get("attack_type_display")) != normalize_label(EXPECTED_DISPLAY_LABELS[project]):
            errors.append(f"wrong display attack label: {project}")
        summary = str(case.get("technical_summary") or "")
        if not summary.startswith("According to CertiK") or not re.search(r"[.!?]$", summary):
            errors.append(f"summary provenance or truncation: {project}")
        source = case.get("source") or {}
        for field in ("source_title", "publisher", "publication_date", "retrieved_at", "source_url"):
            if not source.get(field):
                errors.append(f"missing source field {field}: {project}")

    truebit = cases.get("Truebit") or {}
    expected_exploiters = {
        "0x6C8EC8f14bE7C01672d31CFa5f2CEfeAB2562b50",
        "0xc0454E545a7A715c6D3627f77bEd376a05182FBc",
    }
    if set(truebit.get("source_attributed_exploiter_addresses") or []) != expected_exploiters:
        errors.append("Truebit exploiter completeness")
    expected_downstream = {
        "0xD12f6E0fa7FBF4e3A1c7996E3F0Dd26AB9031a60",
        "0x273589ca3713e7becf42069f9fb3f0c164ce850a",
    }
    if set(truebit.get("downstream_fund_flow_addresses") or []) != expected_downstream:
        errors.append("Truebit downstream role classification")
    if len(truebit.get("source_fund_flow_claims") or []) != 3:
        errors.append("Truebit source fund-flow claim preservation")

    for path in root.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        for token in (LEGACY_SOLANA_ENUM, LEGACY_BRIDGE_ENUM):
            if token in text:
                errors.append(f"public internal enum {token}: {path.name}")
        if "sanctioned mixer" in text.lower():
            errors.append(f"unsupported sanctions wording: {path.name}")
    for path in (root / "cases").glob("*.html"):
        text = path.read_text(encoding="utf-8")
        if LEGACY_BRIDGE_ENUM in text or LEGACY_BRIDGE_LABEL in text:
            errors.append(f"stale attack type: {path.name}")

    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in {".html", ".json", ".md", ".py", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for placeholder in PLACEHOLDERS:
            if placeholder in text:
                blockers.append(f"placeholder {placeholder}: {path.relative_to(root)}")

    internal_links: list[str] = []
    for path in root.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r'href="([^#"]+)', text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            internal_links.append(str((path.parent / target).resolve()))
    for target in internal_links:
        if not Path(target).exists():
            errors.append(f"broken internal link: {target}")

    result = {
        "factual_quality": "PASS" if not errors else "FAIL",
        "application_ready": bool(not errors and not blockers),
        "errors": errors,
        "blockers": blockers,
        "case_count": len(cases),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
