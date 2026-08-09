#!/usr/bin/env python3
"""Render the static portfolio from the sanitized public dataset."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else "UNKNOWN"), quote=True)


def link(url: Any, label: Any) -> str:
    value = str(url or "")
    if not value.startswith(("https://", "http://")):
        return esc(label)
    return f'<a href="{esc(value)}" rel="noreferrer noopener">{esc(label)}</a>'


def bullets(values: Any, cls: str = "") -> str:
    items = values or []
    if not items:
        return '<p class="muted">None recorded.</p>'
    return '<ul class="' + esc(cls) + '">' + "".join(f"<li>{esc(value)}</li>" for value in items) + "</ul>"


def role_group(title: str, values: Any, note: str = "") -> str:
    if not values:
        return ""
    suffix = f'<p class="muted">{esc(note)}</p>' if note else ""
    return f"<h3>{esc(title)}</h3>{bullets(values)}{suffix}"


ATTACK_TYPE_DISPLAY = {
    "TOKEN_LOGIC_PRICE_MANIPULATION_EXPLOIT": "Token Logic / Price Manipulation Exploit",
    "INTEGER_OVERFLOW_TOKEN_MINTING_EXPLOIT": "Integer Overflow / Token Minting Exploit",
    "SIGNATURE_VERIFICATION_AUTHORIZATION_BYPASS": "Signature Verification / Authorization Bypass",
}


def format_attack_label(case: dict[str, Any]) -> str:
    value = case.get("attack_type_display") or ATTACK_TYPE_DISPLAY.get(case.get("attack_type"))
    if value:
        return esc(value)
    return esc(case.get("attack_type")).replace("_", " ").title()


def page(title: str, body: str, *, prefix: str = "", owner_name: Any = "") -> str:
    css = f"{prefix}styles.css"
    nav = f"""
    <nav class="nav wrap" aria-label="Primary navigation">
      <a class="brand" href="{prefix}index.html">{esc(owner_name)} <span>/ on-chain investigations</span></a>
      <div class="nav-links">
        <a href="{prefix}index.html#cases">Cases</a>
        <a href="{prefix}methodology.html">Methodology</a>
        <a href="{prefix}evidence-integrity.html">Evidence integrity</a>
        <a href="{prefix}skills.html">Skills</a>
      </div>
    </nav>
    """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Reproducible, read-only blockchain incident investigation portfolio.">
  <title>{esc(title)} — On-Chain Investigation Portfolio</title>
  <link rel="stylesheet" href="{esc(css)}">
</head>
<body>
  {nav}
  <main>{body}</main>
  <footer class="footer wrap">
    <p>Independent research portfolio. Not affiliated with ChainBounty.</p>
    <p>Address attribution is based on public incident intelligence and reproducible blockchain evidence; it is not a legal determination of criminal liability.</p>
  </footer>
</body>
</html>
"""


def metric_card(value: Any, label: str, note: str = "") -> str:
    return f'<div class="metric"><strong>{esc(value)}</strong><span>{esc(label)}</span><small>{esc(note)}</small></div>'


def case_card(case: dict[str, Any]) -> str:
    validation = case.get("validation") or {}
    return f"""
    <article class="case-card">
      <div class="eyebrow">{esc(case.get('chain'))} · {esc(case.get('incident_date'))}</div>
      <h3>{esc(case.get('project'))}</h3>
      <p>{format_attack_label(case)} with a source-attributed attacker address and exact transaction reproduced on-chain.</p>
      <p class="muted">{esc(case.get('technical_summary'))}</p>
      <div class="tag-row"><span class="tag verified">{esc(validation.get('status'))}</span><span class="tag">{esc(validation.get('provider'))}</span></div>
      <a class="text-link" href="cases/{esc(case.get('slug'))}.html">Read case study →</a>
    </article>
    """


def build_index(data: dict[str, Any]) -> str:
    metrics = data.get("metrics") or {}
    safety = data.get("safety") or {}
    providers = data.get("providers") or {}
    cases = data.get("cases") or []
    owner_name = data.get("owner_name")
    owner_email = data.get("owner_email")
    owner_x = data.get("owner_x")
    github = data.get("github_url")
    github_cta = f'<a class="button secondary" href="{esc(github)}">Public repository</a>' if github else ""
    case_cards = "".join(case_card(case) for case in cases)
    body = f"""
    <section class="hero wrap">
      <div class="hero-copy">
        <p class="eyebrow">Independent research portfolio</p>
        <h1>On-Chain Investigation &amp; Threat Intelligence</h1>
        <p class="lead">Reproducible blockchain evidence, conservative attribution, and read-only forensic validation.</p>
        <p>Backend engineering background with a focus on incident workflows that move from authoritative intelligence to IOC extraction, exact transaction verification, evidence preservation, and structured reporting.</p>
        <div class="button-row"><a class="button" href="#cases">View case studies</a><a class="button secondary" href="methodology.html">View methodology</a>{github_cta}</div>
      </div>
      <aside class="hero-note"><span class="eyebrow">Working principle</span><p>A source assertion is not treated as independent blockchain proof. Missing evidence stays missing.</p></aside>
    </section>

    <section class="section wrap" id="snapshot">
      <div class="section-heading"><p class="eyebrow">Validation snapshot</p><h2>What has actually been reproduced</h2><p>{esc(metrics.get('sample'))}. The figures are bounded sample measurements, not universal accuracy claims.</p></div>
      <div class="metrics-grid">
        {metric_card(metrics.get('incidents_analyzed'), 'Incidents analyzed', 'bounded 2026 sample')}
        {metric_card(str(metrics.get('attacker_and_tx_extracted')) + '/' + str(metrics.get('incidents_analyzed')), 'Attacker + TX evidence extracted', 'source data')}
        {metric_card(str(metrics.get('onchain_verified')) + '/' + str(metrics.get('supported_incidents')), 'Supported incidents reproduced on-chain', 'Ethereum / Gnosis / BSC')}
        {metric_card(metrics.get('tx_not_found'), 'TX not found', 'exact transaction checks')}
        {metric_card(metrics.get('relationship_mismatches'), 'Relationship mismatches', 'attacker relation checks')}
      </div>
    </section>

    <section class="section alt">
      <div class="wrap split">
        <div><p class="eyebrow">What I validate</p><h2>Facts before conclusions</h2><p>Validation checks the exact transaction and its relation to the source-attributed IOC. Blockchain reproduction confirms transaction facts; it does not establish legal identity or criminal liability.</p></div>
        <div class="check-grid">{''.join(f'<div>{esc(label)}</div>' for label in ['Exact transaction hash', 'Chain match', 'Sender / receiver relationship', 'Receipt status', 'Block and timestamp', 'Attacker relationship', 'Malicious contract relationship', 'Source provenance'])}</div>
      </div>
      <div class="wrap provider-grid">
        <div><strong>Ethereum / Gnosis</strong><span>Etherscan V2</span></div>
        <div><strong>BNB Smart Chain</strong><span>Official read-only JSON-RPC</span></div>
        <div><strong>Unsupported chain</strong><span>Remains UNVERIFIED</span></div>
      </div>
    </section>

    <section class="section wrap">
      <div class="section-heading"><p class="eyebrow">Investigation workflow</p><h2>From source intelligence to human review</h2></div>
      <div class="flow"><div>Authoritative<br>incident source</div><i>↓</i><div>IOC extraction<br>&amp; role classification</div><i>↓</i><div>Incident<br>deduplication</div><i>↓</i><div>Exact on-chain<br>validation</div><i>↓</i><div>Evidence<br>package</div><i>↓</i><div>Human<br>review</div></div>
      <div class="role-row"><span>ATTACKER_WALLET</span><span>ATTACKER_CONTRACT</span><span>HELPER_CONTRACT</span><span>VICTIM</span><span>UNKNOWN</span></div>
    </section>

    <section class="section alt" id="cases">
      <div class="wrap"><div class="section-heading"><p class="eyebrow">Selected case studies</p><h2>Bounded incidents, reproducible evidence</h2><p>Only incidents with preserved source attribution and <code>VERIFIED</code> read-only validation are included.</p></div><div class="case-grid">{case_cards}</div></div>
    </section>

    <section class="section wrap">
      <div class="split">
        <div><p class="eyebrow">Architecture</p><h2>A validation system, not a link collector</h2><div class="architecture"><span>Public security intelligence</span><b>↓</b><span>Incident normalization</span><b>↓</b><span>IOC / role extraction</span><b>↓</b><span>On-chain verification</span><b>↓</b><span>Evidence classification</span><b>↓</b><span>Structured report</span></div></div>
        <div><p class="eyebrow">Safety posture</p><h2>Read-only by design</h2>{bullets(['No transaction signing', 'No transaction broadcast', 'No suspicious wallet connection', 'No malicious contract execution', 'No fabricated wallet, TX, victim claim, or screenshot'])}</div>
      </div>
    </section>

    <section class="section alt"><div class="wrap split"><div><p class="eyebrow">About</p><h2>{esc(owner_name)}</h2><p>I am a backend engineer with experience in regulated financial systems and a strong interest in blockchain security, threat intelligence, and reproducible digital investigations.</p><p>My approach combines software engineering discipline with evidence-first on-chain analysis.</p></div><div><p class="eyebrow">Contact</p><p>Email: <strong>{esc(owner_email)}</strong></p><p>X: <strong><a href="{esc(owner_x)}" rel="noreferrer noopener">{esc(owner_x)}</a></strong></p><p class="muted">Public contact details supplied by the portfolio owner.</p></div></div></section>
    <section class="section wrap"><div class="section-heading"><p class="eyebrow">Scope and limits</p><h2>Conservative attribution is a feature</h2><p>Public incident intelligence and on-chain relationships can support a technical lead. They do not replace off-chain evidence, lawful investigative process, or a court's determination.</p><p>Providers used in the bounded sample: {esc(', '.join(f'{key} ({value})' for key, value in providers.items()) or 'Recorded in the case studies')}.</p><p><strong>{esc(metrics.get('tests_passing') or 'UNKNOWN')} automated software tests passed</strong> in the latest local validation run.</p></div></section>
    """
    return page("Home", body, owner_name=data.get("owner_name"))


def build_case(case: dict[str, Any]) -> str:
    validation = case.get("validation") or {}
    source = case.get("source") or {}
    relations = validation.get("relationships") or []
    explorer_links = []
    if case.get("wallet_explorer_url"):
        explorer_links.append(f"<li>{link(case.get('wallet_explorer_url'), 'Wallet explorer')}</li>")
    if case.get("transaction_explorer_url"):
        explorer_links.append(f"<li>{link(case.get('transaction_explorer_url'), 'Transaction explorer')}</li>")
    body = f"""
    <section class="case-hero wrap"><p class="eyebrow">Case study · {esc(case.get('chain'))} · {esc(case.get('incident_date'))}</p><h1>{esc(case.get('project'))}</h1><p class="lead">{esc(case.get('attack_type')).replace('_', ' ').title()} — source-attributed attacker address with exact on-chain relationship reproduced.</p><span class="tag verified">{esc(validation.get('status'))}</span></section>
    <section class="section wrap case-layout">
      <article>
        <h2>Executive summary</h2>
        <dl class="facts"><dt>Project</dt><dd>{esc(case.get('project'))}</dd><dt>Incident date</dt><dd>{esc(case.get('incident_date'))}</dd><dt>Chain</dt><dd>{esc(case.get('chain'))}</dd><dt>Investigation scope</dt><dd>Source attribution and exact referenced transaction validation</dd><dt>Validation status</dt><dd>{esc(validation.get('status'))}</dd></dl>
        <h2>Source provenance</h2>
        <p><strong>{esc(source.get('name'))}</strong></p><p>Publication date: {esc(source.get('publication_date') or 'Not separately preserved')}</p><p>Retrieved date: {esc(source.get('retrieved_at') or 'Not separately preserved')}</p><p>{link(source.get('url'), source.get('url') or 'Source URL not preserved')}</p>
        <h2>Primary IOC</h2>
        <dl class="facts"><dt>Primary attacker</dt><dd><code>{esc(case.get('primary_attacker'))}</code></dd><dt>Primary transaction</dt><dd><code>{esc(case.get('primary_transaction'))}</code></dd><dt>Malicious contract</dt><dd>{bullets(case.get('malicious_contracts'))}</dd></dl>
        <h2>Independent on-chain validation</h2>
        <div class="table-wrap"><table><tbody><tr><th>Provider</th><td>{esc(validation.get('provider'))}</td></tr><tr><th>Chain</th><td>{esc(validation.get('validated_chain'))}</td></tr><tr><th>Block</th><td>{esc(validation.get('block_number'))}</td></tr><tr><th>Timestamp</th><td>{esc(validation.get('block_timestamp'))}</td></tr><tr><th>From</th><td><code>{esc(validation.get('from'))}</code></td></tr><tr><th>To</th><td><code>{esc(validation.get('to'))}</code></td></tr><tr><th>Receipt</th><td>{esc(validation.get('receipt_status'))}</td></tr><tr><th>Attacker relationship</th><td>{esc(', '.join(relations) or 'UNKNOWN')}</td></tr></tbody></table></div>
        <h2>Why the relationship matters</h2>
        <p>The cited source attributes the primary address to the incident. Read-only validation independently reproduced the exact referenced transaction on the stated chain and matched the recorded relationship: <strong>{esc(', '.join(relations) or 'no relationship recorded')}</strong>.</p>
        <p>{esc(case.get('technical_summary'))}</p>
        <h2>Related IOC</h2>{bullets(case.get('related_attacker_addresses'))}
        <h2>Confidence and limitations</h2><h3>Verified fact</h3>{bullets((case.get('confidence') or {}).get('verified_fact'))}<h3>Source-attributed</h3>{bullets((case.get('confidence') or {}).get('source_attributed'))}<h3>Unverified / unknown</h3>{bullets((case.get('confidence') or {}).get('unverified') + (case.get('confidence') or {}).get('unknown'))}<h3>Limitations</h3>{bullets(case.get('limitations'))}
      </article>
      <aside class="case-aside"><div class="aside-card"><p class="eyebrow">Explorer evidence</p><ul>{''.join(explorer_links)}</ul><p class="muted">Only official explorer and source URLs are linked. No malicious website is opened or promoted.</p></div><div class="aside-card disclaimer"><p class="eyebrow">Attribution disclaimer</p><p>Address attribution in this portfolio is based on publicly available incident intelligence and reproducible blockchain evidence. On-chain validation confirms transaction facts and address relationships; it does not constitute a legal determination of criminal liability. Final attribution may require additional off-chain evidence and lawful investigative process.</p></div></aside>
    </section>
    """
    return page(f"{case.get('project')} case study", body, prefix="../")


def build_case_v2(case: dict[str, Any], owner_name: Any = "") -> str:
    validation = case.get("validation") or {}
    source = case.get("source") or {}
    relations = validation.get("relationships") or []
    attack_label = format_attack_label(case)
    explorer_links = []
    if case.get("wallet_explorer_url"):
        explorer_links.append(f"<li>{link(case.get('wallet_explorer_url'), 'Wallet explorer')}</li>")
    if case.get("transaction_explorer_url"):
        explorer_links.append(f"<li>{link(case.get('transaction_explorer_url'), 'Transaction explorer')}</li>")

    role_sections = "".join([
        role_group("Source-attributed exploiter addresses", case.get("source_attributed_exploiter_addresses"), "The source explicitly associates these addresses with the incident narrative."),
        role_group("Downstream fund-flow addresses", case.get("downstream_fund_flow_addresses"), "These addresses appear in the cited fund-flow narrative; appearance does not establish control."),
        role_group("Unknown control addresses", case.get("unknown_control_addresses"), "Control remains unverified in this bounded package."),
    ])

    source_claim_rows = []
    for item in case.get("source_fund_flow_claims") or []:
        source_claim_rows.append(
            "<tr>"
            f"<td>{esc(item.get('label'))}</td>"
            f"<td><code>{esc(item.get('from'))}</code></td>"
            f"<td><code>{esc(item.get('to'))}</code></td>"
            f"<td><code>{esc(item.get('tx_hash'))}</code></td>"
            f"<td>{esc(item.get('chain'))}</td>"
            f"<td>{esc(item.get('amount'))}</td>"
            f"<td>{esc(item.get('block'))}</td>"
            f"<td>{esc(item.get('timestamp'))}</td>"
            f"<td>{esc(item.get('evidence_status'))}</td>"
            f"<td>{esc(item.get('source_attribution_status'))}</td>"
            f"<td>{' '.join(link(url, 'evidence') for url in item.get('evidence_urls') or [])}</td>"
            "</tr>"
        )
    source_claim_section = ""
    if source_claim_rows:
        source_claim_section = (
            '<h3>Source-reported fund flow — not independently verified</h3>'
            '<p>These claims are preserved from the authoritative source. Missing TX, block, or timestamp values remain unknown; no exact hop is presented as reproduced.</p>'
            '<div class="table-wrap"><table><thead><tr><th>Flow</th><th>From</th><th>To</th><th>TX hash</th><th>Chain</th><th>Asset / amount</th><th>Block</th><th>Timestamp</th><th>Evidence status</th><th>Attribution status</th><th>Sources</th></tr></thead><tbody>'
            + "".join(source_claim_rows)
            + "</tbody></table></div>"
        )

    flow_rows = []
    for item in case.get("fund_flow") or []:
        destination = esc(item.get("to"))
        if item.get("to_label"):
            destination += f" — {esc(item.get('to_label'))}"
        flow_rows.append(
            "<tr>"
            f"<td>{esc(item.get('hop'))}</td>"
            f"<td><code>{esc(item.get('from'))}</code></td>"
            f"<td><code>{destination}</code></td>"
            f"<td><code>{esc(item.get('tx_hash'))}</code></td>"
            f"<td>{esc(item.get('chain'))}</td>"
            f"<td>{esc(item.get('asset'))} {esc(item.get('amount'))}</td>"
            f"<td>{esc(item.get('timestamp'))}</td>"
            f"<td>{esc(item.get('evidence_status'))}</td>"
            f"<td>{esc(item.get('source_attribution_status'))}</td>"
            "</tr>"
        )
    fund_flow_section = ""
    if flow_rows or source_claim_section or case.get("unverified_fund_flow_notes"):
        fund_flow_table = ""
        if flow_rows:
            fund_flow_table = (
                '<div class="table-wrap"><table><thead><tr><th>Hop</th><th>From</th><th>To</th><th>TX hash</th><th>Chain</th><th>Asset / amount</th><th>Timestamp</th><th>Evidence status</th><th>Source attribution status</th></tr></thead><tbody>'
                + "".join(flow_rows)
                + "</tbody></table></div>"
            )
        fund_flow_section = (
            '<h2>Fund-flow extension</h2>'
            '<p>Only hops with a preserved transaction reference and read-only explorer evidence are listed as verified. Downstream control is not inferred from address proximity.</p>'
            + fund_flow_table
            + source_claim_section
            + bullets(case.get("unverified_fund_flow_notes"))
        )

    confidence = case.get("confidence") or {}
    uncertain = (confidence.get("unverified") or []) + (confidence.get("unknown") or [])
    body = f"""
    <section class="case-hero wrap"><p class="eyebrow">Case study &middot; {esc(case.get('chain'))} &middot; {esc(case.get('incident_date'))}</p><h1>{esc(case.get('project'))}</h1><p class="lead">{attack_label} &mdash; source-attributed attacker address with exact on-chain relationship reproduced.</p><span class="tag verified">{esc(validation.get('status'))}</span></section>
    <section class="section wrap case-layout">
      <article>
        <h2>Executive summary</h2>
        <dl class="facts"><dt>Project</dt><dd>{esc(case.get('project'))}</dd><dt>Incident date</dt><dd>{esc(case.get('incident_date'))}</dd><dt>Chain</dt><dd>{esc(case.get('chain'))}</dd><dt>Attack type</dt><dd>{attack_label}</dd><dt>Investigation scope</dt><dd>Source attribution and exact referenced transaction validation</dd><dt>Validation status</dt><dd>{esc(validation.get('status'))}</dd></dl>
        <p>{esc(case.get('technical_summary'))}</p>
        <h2>Source provenance</h2>
        <p><strong>{esc(source.get('source_title') or source.get('name'))}</strong></p><p>Publisher: {esc(source.get('publisher') or source.get('name') or 'UNKNOWN')}</p><p>Publication date: {esc(source.get('publication_date') or 'Not separately preserved')}</p><p>Retrieved at: {esc(source.get('retrieved_at') or 'Not separately preserved')}</p><p>{link(source.get('source_url') or source.get('url'), source.get('source_url') or source.get('url') or 'Source URL not preserved')}</p>
        <h2>Primary IOC</h2>
        <dl class="facts"><dt>Primary attacker address</dt><dd><code>{esc(case.get('primary_attacker_address') or case.get('primary_attacker'))}</code></dd><dt>Primary transaction</dt><dd><code>{esc(case.get('primary_transaction'))}</code></dd><dt>Malicious contract</dt><dd>{bullets(case.get('malicious_contracts'))}</dd></dl>
        <h2>Independent on-chain validation</h2>
        <div class="table-wrap"><table><tbody><tr><th>Provider</th><td>{esc(validation.get('provider'))}</td></tr><tr><th>Chain</th><td>{esc(validation.get('validated_chain'))}</td></tr><tr><th>Block</th><td>{esc(validation.get('block_number'))}</td></tr><tr><th>Timestamp</th><td>{esc(validation.get('block_timestamp'))}</td></tr><tr><th>From</th><td><code>{esc(validation.get('from'))}</code></td></tr><tr><th>To</th><td><code>{esc(validation.get('to'))}</code></td></tr><tr><th>Receipt</th><td>{esc(validation.get('receipt_status'))}</td></tr><tr><th>Attacker relationship</th><td>{esc(', '.join(relations) or 'UNKNOWN')}</td></tr></tbody></table></div>
        <h2>Why the relationship matters</h2>
        <p>The cited source attributes the primary address to the incident. Read-only validation independently reproduced the exact referenced transaction on the stated chain and matched the recorded relationship: <strong>{esc(', '.join(relations) or 'no relationship recorded')}</strong>.</p>
        <h2>Address-role classification</h2>{role_sections}
{fund_flow_section}
        <h2>Confidence and limitations</h2><h3>Verified fact</h3>{bullets(confidence.get('verified_fact'))}<h3>Source-attributed</h3>{bullets(confidence.get('source_attributed'))}<h3>Unverified / unknown</h3>{bullets(uncertain)}<h3>Limitations</h3>{bullets(case.get('limitations'))}
      </article>
      <aside class="case-aside"><div class="aside-card"><p class="eyebrow">Explorer evidence</p><ul>{''.join(explorer_links)}</ul><p class="muted">Only official explorer and source URLs are linked. No malicious website is opened or promoted.</p></div><div class="aside-card disclaimer"><p class="eyebrow">Attribution disclaimer</p><p>Address attribution in this portfolio is based on publicly available incident intelligence and reproducible blockchain evidence. On-chain validation confirms transaction facts and address relationships; it does not constitute a legal determination of criminal liability. Final attribution may require additional off-chain evidence and lawful investigative process.</p></div></aside>
    </section>
    """
    return page(f"{case.get('project')} case study", body, prefix="../", owner_name=owner_name)


def build_methodology(owner_name: Any = "") -> str:
    sections = [
        ("1. Source selection", "Use authoritative public incident analysis and preserve the source URL and retrieval context. A source assertion is not treated as independent on-chain proof."),
        ("2. IOC extraction", "Extract only addresses, contracts, and transaction hashes explicitly supported by the source. Do not infer an attacker from proximity alone."),
        ("3. Role classification", "Separate ATTACKER_WALLET, ATTACKER_CONTRACT, HELPER_CONTRACT, PROTOCOL/TOKEN, VICTIM, and UNKNOWN roles."),
        ("4. Independent blockchain validation", "Query the stated chain in read-only mode. Reproduce the exact transaction, chain, sender/receiver relationship, receipt, block, and timestamp."),
        ("5. Evidence preservation", "Keep the source, validation fields, explorer references, and evidence summary together so another reviewer can reproduce the claim."),
        ("6. Confidence classification", "Distinguish VERIFIED FACT, SOURCE-ATTRIBUTED, INFERENCE, UNVERIFIED, and UNKNOWN. Conflicting evidence blocks promotion."),
        ("7. Human review", "Duplicate checks, current form fields, and final submission decisions remain manual. No ChainBounty page is crawled or submitted by the workflow."),
        ("8. Limitations", "On-chain data confirms transactions and relationships, not legal identity. Downstream tracing, exchange attribution, and off-chain evidence require additional lawful work."),
    ]
    body = '<section class="page-head wrap"><p class="eyebrow">Methodology</p><h1>Investigation Methodology</h1><p class="lead">A bounded, reproducible workflow for evidence-first blockchain incident analysis.</p></section><section class="section wrap prose">' + "".join(f"<h2>{esc(title)}</h2><p>{esc(text)}</p>" for title, text in sections) + '</section>'
    return page("Methodology", body, owner_name=owner_name)


def build_integrity(owner_name: Any = "") -> str:
    body = f"""
    <section class="page-head wrap"><p class="eyebrow">Evidence integrity</p><h1>Read-only by design</h1><p class="lead">The workflow is designed to preserve evidence without interacting with suspicious applications or changing blockchain state.</p></section>
    <section class="section wrap prose"><h2>Never performed</h2>{bullets(['Transaction signing', 'Transaction broadcasting', 'Wallet connection to suspicious applications', 'Malicious contract execution', 'Fabricated wallets', 'Fabricated transactions', 'Fabricated victim claims', 'Fabricated screenshots'])}<h2>Always preserved</h2>{bullets(['Source provenance', 'Exact transaction hash', 'Chain and block context', 'Sender / receiver relationship', 'Validation status', 'Unsupported and conflicting findings'])}<h2>Publication boundary</h2><p>The public portfolio contains only a sanitized dataset. API keys, tokens, cookies, login data, internal paths, private DB records, and unnecessary victim information are excluded.</p></section>
    """
    return page("Evidence integrity", body, owner_name=owner_name)


def build_skills(owner_name: Any = "") -> str:
    skills = ["Python", "Blockchain transaction analysis", "Ethereum", "BNB Smart Chain", "Gnosis", "Etherscan V2", "JSON-RPC", "IOC extraction", "Address-role classification", "Incident deduplication", "Evidence validation", "Source provenance", "Reproducible investigation workflows", "Structured forensic reporting"]
    body = f'<section class="page-head wrap"><p class="eyebrow">Capabilities</p><h1>Skills in demonstrated scope</h1><p class="lead">Only capabilities exercised by the current project are listed.</p></section><section class="section wrap"><div class="skill-grid">{"".join(f"<div class=\"skill\">{esc(skill)}</div>" for skill in skills)}</div><p class="muted">No claims are made for commercial intelligence platforms or tools not used in this workflow.</p></section>'
    return page("Skills", body, owner_name=owner_name)


def write_site(data_path: Path, root: Path) -> dict[str, Any]:
    data = json.loads(data_path.read_text(encoding="utf-8"))
    root.mkdir(parents=True, exist_ok=True)
    (root / "cases").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "portfolio.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "index.html").write_text(build_index(data), encoding="utf-8")
    owner_name = data.get("owner_name")
    (root / "methodology.html").write_text(build_methodology(owner_name), encoding="utf-8")
    (root / "evidence-integrity.html").write_text(build_integrity(owner_name), encoding="utf-8")
    (root / "skills.html").write_text(build_skills(owner_name), encoding="utf-8")
    for case in data.get("cases") or []:
        (root / "cases" / f"{case['slug']}.html").write_text(build_case_v2(case, owner_name), encoding="utf-8")
    css = """/* Local, dependency-free styles for the public portfolio. */
:root { --ink:#16202a; --muted:#5b6875; --line:#d9e0e6; --paper:#f7f8f6; --panel:#ffffff; --accent:#0e6b62; --accent-soft:#e3f1ed; --dark:#10252b; --max:1120px; }
* { box-sizing:border-box; } html { scroll-behavior:smooth; } body { margin:0; color:var(--ink); background:var(--paper); font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height:1.65; } a { color:var(--accent); } code { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:.9em; overflow-wrap:anywhere; } .wrap { width:min(calc(100% - 40px), var(--max)); margin-inline:auto; } .nav { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:24px; border-bottom:1px solid var(--line); } .brand { color:var(--ink); font-weight:750; text-decoration:none; letter-spacing:-.02em; } .brand span { color:var(--muted); font-weight:500; } .nav-links { display:flex; gap:20px; flex-wrap:wrap; justify-content:flex-end; } .nav-links a { color:var(--muted); text-decoration:none; font-size:.92rem; } .nav-links a:hover { color:var(--ink); } .hero { display:grid; grid-template-columns:1.5fr .75fr; gap:72px; padding:96px 0 82px; align-items:end; } h1,h2,h3 { line-height:1.15; letter-spacing:-.035em; margin:0 0 18px; } h1 { font-size:clamp(2.8rem, 7vw, 5.7rem); max-width:900px; } h2 { font-size:clamp(1.75rem, 3vw, 2.5rem); } h3 { font-size:1.15rem; } p { margin:0 0 18px; } .lead { font-size:clamp(1.2rem, 2.3vw, 1.55rem); color:#33434d; max-width:780px; } .eyebrow { color:var(--accent); font-size:.74rem; font-weight:800; letter-spacing:.12em; text-transform:uppercase; margin-bottom:14px; } .hero-note { border-left:4px solid var(--accent); padding:20px 0 12px 24px; font-size:1.08rem; } .button-row { display:flex; gap:12px; flex-wrap:wrap; margin-top:30px; } .button { display:inline-block; padding:11px 17px; border-radius:5px; color:#fff; background:var(--accent); text-decoration:none; font-weight:700; } .button.secondary { color:var(--ink); background:transparent; border:1px solid var(--line); } .section { padding:86px 0; } .section.alt { background:#eef2f0; } .section-heading { max-width:760px; margin-bottom:30px; } .metrics-grid { display:grid; grid-template-columns:repeat(5,1fr); border-top:1px solid var(--line); border-bottom:1px solid var(--line); } .metric { padding:25px 18px 24px 0; border-right:1px solid var(--line); margin-right:18px; } .metric:last-child { border-right:0; } .metric strong { display:block; font-size:2.25rem; letter-spacing:-.06em; } .metric span,.metric small { display:block; } .metric span { font-weight:700; } .metric small,.muted { color:var(--muted); font-size:.88rem; } .split { display:grid; grid-template-columns:1fr 1fr; gap:70px; align-items:start; } .check-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; } .check-grid div,.skill,.provider-grid div { padding:15px; background:var(--panel); border:1px solid var(--line); } .provider-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-top:34px; } .provider-grid strong,.provider-grid span { display:block; } .provider-grid span { color:var(--muted); margin-top:4px; } .flow { display:flex; align-items:center; gap:12px; overflow-x:auto; padding:20px 0 16px; } .flow div { flex:1; min-width:128px; padding:18px 12px; text-align:center; background:var(--dark); color:#fff; border-radius:4px; font-weight:700; line-height:1.25; } .flow i { color:var(--accent); font-style:normal; font-size:1.3rem; } .role-row { display:flex; flex-wrap:wrap; gap:8px; } .role-row span,.tag { display:inline-block; padding:4px 9px; border:1px solid var(--line); border-radius:999px; color:var(--muted); font-size:.75rem; font-weight:700; } .case-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:18px; } .case-card { background:var(--panel); border:1px solid var(--line); padding:25px; display:flex; flex-direction:column; min-height:260px; } .case-card h3 { margin-bottom:10px; } .case-card .text-link { margin-top:auto; font-weight:750; text-decoration:none; } .tag-row { display:flex; gap:8px; flex-wrap:wrap; margin:12px 0 20px; } .tag.verified { color:#0a5e46; background:var(--accent-soft); border-color:#afd9cc; } .architecture { display:grid; gap:7px; max-width:440px; } .architecture span { padding:11px 15px; border:1px solid var(--line); background:var(--panel); } .architecture b { color:var(--accent); text-align:center; } .page-head,.case-hero { padding:82px 0 50px; } .page-head h1,.case-hero h1 { font-size:clamp(2.5rem, 6vw, 4.8rem); } .case-hero { border-bottom:1px solid var(--line); } .case-layout { display:grid; grid-template-columns:minmax(0,1fr) 300px; gap:70px; } .case-layout h2 { margin-top:42px; } .case-layout h2:first-child { margin-top:0; } .case-layout h3 { margin-top:28px; margin-bottom:8px; font-size:1rem; letter-spacing:0; } .facts { display:grid; grid-template-columns:180px 1fr; border-top:1px solid var(--line); } .facts dt,.facts dd { padding:12px 0; border-bottom:1px solid var(--line); margin:0; } .facts dt { color:var(--muted); font-weight:700; } .table-wrap { overflow-x:auto; } table { width:100%; border-collapse:collapse; } th,td { text-align:left; padding:12px 14px; border:1px solid var(--line); vertical-align:top; } th { width:220px; background:#eef2f0; } .case-aside { position:sticky; top:20px; align-self:start; } .aside-card { padding:22px; background:var(--panel); border:1px solid var(--line); margin-bottom:16px; } .aside-card ul { padding-left:20px; } .disclaimer { border-top:4px solid var(--accent); font-size:.9rem; } .prose { max-width:820px; } .prose h2 { margin-top:42px; } .prose h2:first-child { margin-top:0; } .skill-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:28px; } .skill { font-weight:700; } .footer { border-top:1px solid var(--line); padding:35px 0 55px; color:var(--muted); font-size:.84rem; } @media (max-width:800px) { .nav { align-items:flex-start; padding:18px 0; flex-direction:column; } .nav-links { justify-content:flex-start; gap:12px; } .hero,.split,.case-layout { grid-template-columns:1fr; gap:35px; } .hero { padding:65px 0 55px; } .metrics-grid { grid-template-columns:repeat(2,1fr); } .metric { border-bottom:1px solid var(--line); } .provider-grid,.case-grid { grid-template-columns:1fr; } .case-aside { position:static; } .skill-grid { grid-template-columns:1fr 1fr; } } @media print { .nav-links,.button-row,.footer { display:none; } body { background:#fff; } .section,.page-head,.case-hero { padding:28px 0; } a { color:inherit; text-decoration:none; } }
"""
    (root / "styles.css").write_text(css, encoding="utf-8")
    return {"root": str(root), "cases": [item.get("project") for item in data.get("cases") or []]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/portfolio.json"))
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    print(json.dumps(write_site(args.data, args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
