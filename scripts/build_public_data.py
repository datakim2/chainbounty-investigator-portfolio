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

# These public-case facts were rechecked against the cited CertiK incident
# pages before the 2026-08-09 publication build. They intentionally override
# stale or truncated fields in the internal DB without copying that DB into
# the public repository.
CASE_FACTS: dict[str, dict[str, Any]] = {
    "movie token": {
        "source_title": "Movie Token Incident Analysis - CertiK",
        "publication_date": "2026-03-19",
        "attack_type": "TOKEN_LOGIC_PRICE_MANIPULATION_EXPLOIT",
        "technical_summary": (
            "On 10 March 2026, the Movie Token (MT) contract was exploited for approximately $242,000 because its sell logic double-counted tokens sent to the liquidity pair and to pendingBurnAmount. "
            "The later burn created an artificial supply shock, distorted the MT price, and enabled the attacker to drain value from the pool."
        ),
    },
    "truebit": {
        "source_title": "Truebit Incident Analysis - CertiK",
        "publication_date": "2026-01-08",
        "attack_type": "INTEGER_OVERFLOW_TOKEN_MINTING_EXPLOIT",
        "technical_summary": (
            "On 8 January 2026, Truebit was exploited for approximately $26.6M through an integer-overflow vulnerability in pre-0.8 Solidity arithmetic. "
            "The reported exploiter used the overflow to mint TRU for zero ETH and swap the minted tokens for ETH; the bounded public case validates the first source-attributed exploiter and its referenced transaction."
        ),
    },
    "gnosispay": {
        "source_title": "GnosisPay Incident Analysis - CertiK",
        "publication_date": "2026-06-04",
        "attack_type": "SIGNATURE_VERIFICATION_AUTHORIZATION_BYPASS",
        "technical_summary": (
            "On 1 June 2026, an attacker drained dozens of GnosisPay Safes after a signature-verification flaw in the GnosisPay Delay module accepted attacker-crafted nested signature data. "
            "The crafted verification path reached attacker-prepared EIP-1271 contracts that returned the expected magic value, allowing queued transactions to transfer EURe and GNO from victim Safes."
        ),
        "source_attributed_exploiter_addresses": [
            "0x81BA8A2b895D30280bca199C2Ff75f3F058d4C6c",
            "0xb1834575349c6eb56675c35b4109c3d3a77dd2fc",
        ],
        "downstream_fund_flow_addresses": [
            "0xb1834575349c6eb56675c35b4109c3d3a77dd2fc",
            "0xcce200e0df2f6d47ccffc0e64e6fddc145b13f67",
            "0x3eb18b54a2f7500c3a581197cf7d9fbd62516160",
            "0x0dda0f6aa7b3e0ec1273c4e47c56e7bed57a308c",
            "0x31c2c0c4ab37a89d38968735f8ad9f04e332576a",
        ],
        "unknown_control_addresses": [
            "0xcce200e0df2f6d47ccffc0e64e6fddc145b13f67",
            "0x3eb18b54a2f7500c3a581197cf7d9fbd62516160",
            "0x0dda0f6aa7b3e0ec1273c4e47c56e7bed57a308c",
            "0x31c2c0c4ab37a89d38968735f8ad9f04e332576a",
        ],
        "fund_flow": [
            {
                "hop": 1,
                "chain": "ethereum",
                "from": "0x81BA8A2b895D30280bca199C2Ff75f3F058d4C6c",
                "to": "0x89c6340B1a1f4b25D36cd8B063D49045caF3f818",
                "to_label": "LI.FI: Permit2 Proxy 2",
                "tx_hash": "0x1138fd1bb2708062cb577b0ffb275c847a1964efff019156768e530e3a52dd7e",
                "asset": "USDT",
                "amount": "246,388.411645",
                "timestamp": "2026-06-01T06:33:11Z",
                "evidence_status": "VERIFIED_SOURCE_AND_EXPLORER",
                "source_attribution_status": "SOURCE_ATTRIBUTED_EXPLOIT_WALLET_OUTFLOW",
                "evidence_urls": [
                    "https://www.certik.com/blog/gnosispay-incident-analysis",
                    "https://etherscan.io/tx/0x1138fd1bb2708062cb577b0ffb275c847a1964efff019156768e530e3a52dd7e",
                ],
            }
        ],
        "unverified_fund_flow_notes": [
            "CertiK describes subsequent routing through LI.FI/Relay and an XMR split, but those downstream hops are not independently reproduced by the bounded local validator and remain UNVERIFIED in this portfolio."
        ],
    },
}
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


def public_case(incident: dict[str, Any], *, source_retrieved_at: str | None = None) -> dict[str, Any]:
    project = text(incident.get("project"))
    facts = CASE_FACTS.get(project.lower(), {})
    attackers = unique(incident.get("attacker_addresses"))
    matched = unique(incident.get("matched_attacker_addresses"))
    wallet = matched[0] if matched else attackers[0] if attackers else None
    tx = text(incident.get("validated_tx_hash")) or (unique(incident.get("transaction_hashes")) or [None])[0]
    chain = text(incident.get("chain")).lower()
    address_url = existing_address_url(incident, wallet) if wallet else None
    address_url = address_url or explorer_url(chain, wallet)
    tx_url = explorer_url(chain, tx, tx=True)
    source_exploiters = unique(facts.get("source_attributed_exploiter_addresses")) or attackers
    related = [value for value in source_exploiters if not wallet or value.lower() != wallet.lower()]
    source = text(incident.get("source_url"))
    relations = relation_values(incident)
    return {
        "project": project or "Unknown project",
        "slug": project.lower().replace("/", "-").replace(" ", "-") or "incident",
        "incident_date": text(incident.get("incident_date")) or "UNKNOWN",
        "chain": text(incident.get("chain")) or "UNKNOWN",
        "attack_type": text(facts.get("attack_type")) or text(incident.get("attack_type")) or "OTHER_WEB3_THREAT",
        "source": {
            "name": "CertiK official incident analysis" if text(incident.get("source")) == "certik_official_incident_analysis" else text(incident.get("source")) or "UNKNOWN",
            "source_title": text(facts.get("source_title")) or None,
            "source_url": source or None,
            "url": source or None,
            "publication_date": facts.get("publication_date") or incident.get("publication_date") or None,
            "retrieved_at": source_retrieved_at or incident.get("source_retrieved_at") or incident.get("retrieved_at") or None,
        },
        "primary_attacker": wallet,
        "primary_attacker_address": wallet,
        "source_attributed_exploiter_addresses": source_exploiters,
        "downstream_fund_flow_addresses": unique(facts.get("downstream_fund_flow_addresses")),
        "unknown_control_addresses": unique(facts.get("unknown_control_addresses")),
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
        "technical_summary": text(facts.get("technical_summary")) or text(incident.get("technical_description")) or "A technical summary was not preserved in the public dataset.",
        "fund_flow": facts.get("fund_flow") or [],
        "unverified_fund_flow_notes": unique(facts.get("unverified_fund_flow_notes")),
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


def build(db_path: Path, output: Path, tests_passing: int | None = None, github_url: str | None = None, source_retrieved_at: str | None = None) -> dict[str, Any]:
    db = json.loads(db_path.read_text(encoding="utf-8"))
    incidents = [item for item in db.get("incidents", []) if isinstance(item, dict)]
    supported = [item for item in incidents if text(item.get("chain")).lower() in SUPPORTED_CHAINS]
    verified = [item for item in supported if text(item.get("onchain_validation_status")) == "VERIFIED"]
    preferred = {name.lower(): name for name in PREFERRED_CASES}
    selected: list[dict[str, Any]] = []
    for name in PREFERRED_CASES:
        found = next((item for item in verified if text(item.get("project")).lower() == name.lower()), None)
        if found:
            selected.append(public_case(found, source_retrieved_at=source_retrieved_at))
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
    parser.add_argument("--source-retrieved-at")
    args = parser.parse_args()
    payload = build(args.source_db, args.output, args.tests_passing, args.github_url, args.source_retrieved_at)
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
