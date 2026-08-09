#!/usr/bin/env python3
"""Build the minimal public portfolio dataset from the private Hunter DB.

The input DB path is supplied at runtime and is never copied into the output.
Only public incident IOCs, source URLs, and validation facts are emitted.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_CHAINS = {"ethereum", "eth", "gnosis", "bsc", "bnb", "bnb smart chain"}
PREFERRED_CASES = ["Movie Token", "Truebit", "GnosisPay"]
ADDRESS_EXPLORERS = {
    "ethereum": "https://etherscan.io/address/{value}",
    "eth": "https://etherscan.io/address/{value}",
    "bsc": "https://bscscan.com/address/{value}",
    "bnb": "https://bscscan.com/address/{value}",
    "bnb smart chain": "https://bscscan.com/address/{value}",
    "gnosis": "https://gnosisscan.io/address/{value}",
}
TX_EXPLORERS = {
    "ethereum": "https://etherscan.io/tx/{value}",
    "eth": "https://etherscan.io/tx/{value}",
    "bsc": "https://bscscan.com/tx/{value}",
    "bnb": "https://bscscan.com/tx/{value}",
    "bnb smart chain": "https://bscscan.com/tx/{value}",
    "gnosis": "https://gnosisscan.io/tx/{value}",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def unique(values: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        current = text(value)
        if current and current.lower() not in seen:
            seen.add(current.lower())
            result.append(current)
    return result


def explorer_url(chain: Any, value: Any, *, tx: bool = False) -> str | None:
    mapping = TX_EXPLORERS if tx else ADDRESS_EXPLORERS
    template = mapping.get(text(chain).lower())
    return template.format(value=text(value)) if template and text(value) else None


def existing_address_url(incident: dict[str, Any], address: str) -> str | None:
    needle = address.lower()
    for url in incident.get("explorer_urls") or []:
        if needle in text(url).lower():
            return text(url)
    return None


def provider_label(value: Any) -> str:
    source = text(value)
    if source == "etherscan_v2_validator":
        return "Etherscan V2"
    if source == "bsc_rpc_validator":
        return "Official BNB Smart Chain read-only JSON-RPC"
    return source or "Not configured"


def relation_values(incident: dict[str, Any]) -> list[str]:
    validation = incident.get("onchain_validation") if isinstance(incident.get("onchain_validation"), dict) else {}
    return unique(validation.get("relationships") or incident.get("relationships") or [])


def public_case(incident: dict[str, Any]) -> dict[str, Any]:
    attackers = unique(incident.get("attacker_addresses"))
    matched = unique(incident.get("matched_attacker_addresses"))
    wallet = matched[0] if matched else attackers[0] if attackers else None
    tx = text(incident.get("validated_tx_hash")) or (unique(incident.get("transaction_hashes")) or [None])[0]
    chain = text(incident.get("chain")).lower()
    address_url = existing_address_url(incident, wallet) if wallet else None
    address_url = address_url or explorer_url(chain, wallet)
    tx_url = explorer_url(chain, tx, tx=True)
    related = [value for value in attackers if not wallet or value.lower() != wallet.lower()]
    source = text(incident.get("source_url"))
    relations = relation_values(incident)
    return {
        "project": text(incident.get("project")) or "Unknown project",
        "slug": text(incident.get("project")).lower().replace("/", "-").replace(" ", "-") or "incident",
        "incident_date": text(incident.get("incident_date")) or "UNKNOWN",
        "chain": text(incident.get("chain")) or "UNKNOWN",
        "attack_type": text(incident.get("attack_type")) or "OTHER_WEB3_THREAT",
        "source": {
            "name": "CertiK official incident analysis" if text(incident.get("source")) == "certik_official_incident_analysis" else text(incident.get("source")) or "UNKNOWN",
            "url": source or None,
            "publication_date": incident.get("publication_date") or None,
            "retrieved_at": incident.get("source_retrieved_at") or incident.get("retrieved_at") or None,
        },
        "primary_attacker": wallet,
        "related_attacker_addresses": related,
        "malicious_contracts": unique(incident.get("malicious_contracts")),
        "primary_transaction": tx,
        "transaction_hashes": unique(incident.get("transaction_hashes")),
        "wallet_explorer_url": address_url,
        "transaction_explorer_url": tx_url,
        "validation": {
            "provider": provider_label(incident.get("validation_provider")),
            "provider_raw": text(incident.get("validation_provider")) or None,
            "status": text(incident.get("onchain_validation_status")) or "NOT_CHECKED",
            "validated_chain": text(incident.get("validated_chain")) or chain,
            "block_number": incident.get("block_number"),
            "block_timestamp": incident.get("block_timestamp"),
            "from": incident.get("tx_from"),
            "to": incident.get("tx_to"),
            "receipt_status": incident.get("receipt_status"),
            "matched_attacker_addresses": matched,
            "matched_malicious_contracts": unique(incident.get("matched_malicious_contracts")),
            "relationships": relations,
        },
        "technical_summary": text(incident.get("technical_description")) or "A technical summary was not preserved in the public dataset.",
        "loss_amount": text(incident.get("loss_amount")) or None,
        "confidence": {
            "verified_fact": [
                "The exact referenced transaction exists on the stated chain.",
                "The recorded sender/receiver relationship was reproduced read-only.",
            ],
            "source_attributed": ["The attacker address attribution originates from the cited authoritative incident analysis."],
            "inference": [],
            "unverified": ["Legal identity and criminal liability are not established by this portfolio."],
            "unknown": ["Downstream fund-flow tracing and off-chain identity attribution are outside this bounded sample."],
        },
        "limitations": [
            "Malicious attribution currently originates from one authoritative public incident source.",
            "Blockchain validation confirms transaction facts and address relationships, not legal culpability.",
            "Downstream fund-flow tracing may be incomplete.",
        ],
    }


def build(db_path: Path, output: Path, tests_passing: int | None = None, github_url: str | None = None) -> dict[str, Any]:
    db = json.loads(db_path.read_text(encoding="utf-8"))
    incidents = [item for item in db.get("incidents", []) if isinstance(item, dict)]
    supported = [item for item in incidents if text(item.get("chain")).lower() in SUPPORTED_CHAINS]
    verified = [item for item in supported if text(item.get("onchain_validation_status")) == "VERIFIED"]
    preferred = {name.lower(): name for name in PREFERRED_CASES}
    selected: list[dict[str, Any]] = []
    for name in PREFERRED_CASES:
        found = next((item for item in verified if text(item.get("project")).lower() == name.lower()), None)
        if found:
            selected.append(public_case(found))
    metrics = {
        "incidents_analyzed": len(incidents),
        "attacker_and_tx_extracted": sum(bool(unique(item.get("attacker_addresses"))) and bool(unique(item.get("transaction_hashes"))) for item in incidents),
        "supported_incidents": len(supported),
        "onchain_verified": len(verified),
        "tx_not_found": sum(text(item.get("onchain_validation_status")) == "TX_NOT_FOUND" for item in incidents),
        "relationship_mismatches": sum(text(item.get("onchain_validation_status")) == "MISMATCH" for item in incidents),
        "unsupported_incidents": sum(text(item.get("onchain_validation_status")) == "UNSUPPORTED_CHAIN" for item in incidents),
        "tests_passing": tests_passing,
        "sample": "Bounded 2026 incident sample",
    }
    providers = {}
    for item in incidents:
        provider = provider_label(item.get("validation_provider"))
        if provider != "Not configured":
            providers[provider] = providers.get(provider, 0) + 1
    payload = {
        "generated_at": now_iso(),
        "portfolio_title": "On-Chain Investigation & Threat Intelligence Portfolio",
        "owner_name": "[YOUR NAME]",
        "owner_email": "[YOUR PUBLIC EMAIL]",
        "owner_x": "[YOUR X PROFILE]",
        "github_url": github_url,
        "independent_project": True,
        "not_affiliated_with_chainbounty": True,
        "metrics": metrics,
        "providers": providers,
        "cases": selected,
        "preferred_cases_missing": [name for name in PREFERRED_CASES if name.lower() not in {text(item.get("project")).lower() for item in incidents}],
        "safety": {
            "transaction_signing": 0,
            "transaction_broadcasting": 0,
            "wallet_connections": 0,
            "malicious_contract_execution": 0,
            "fabricated_wallets": 0,
            "fabricated_transactions": 0,
            "fabricated_victim_claims": 0,
            "fabricated_screenshots": 0,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-db", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("data/portfolio.json"))
    parser.add_argument("--tests-passing", type=int)
    parser.add_argument("--github-url")
    args = parser.parse_args()
    payload = build(args.source_db, args.output, args.tests_passing, args.github_url)
    print(json.dumps({
        "output": str(args.output),
        "incidents_analyzed": payload["metrics"]["incidents_analyzed"],
        "supported_incidents": payload["metrics"]["supported_incidents"],
        "onchain_verified": payload["metrics"]["onchain_verified"],
        "cases": [item["project"] for item in payload["cases"]],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
