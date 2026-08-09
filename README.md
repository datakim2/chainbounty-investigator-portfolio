# On-Chain Investigation & Threat Intelligence Portfolio

This is an independent research portfolio demonstrating reproducible,
read-only blockchain incident investigation.

The portfolio moves from authoritative public incident intelligence to:

- attacker-wallet and contract role extraction;
- exact transaction verification;
- sender/receiver and contract relationship checks;
- source provenance and evidence preservation;
- structured, human-reviewable forensic reporting.

## Validation snapshot

The figures in `data/portfolio.json` are generated from a bounded local
incident sample. They are not claims of universal accuracy or legal identity.
Unsupported chains remain explicitly unverified.

## Selected cases

- Movie Token — BNB Smart Chain
- Truebit — Ethereum
- GnosisPay — Gnosis

## Methodology and evidence integrity

See [Methodology](methodology.html) and [Evidence integrity](evidence-integrity.html).
The workflow performs no transaction signing, broadcasting, suspicious wallet
connection, or malicious-contract execution. It does not fabricate wallets,
transactions, victim claims, or screenshots.

## Build

The public dataset is generated from a private source DB at build time. The
private DB itself is never copied into this repository:

```powershell
python scripts/build_public_data.py --source-db PATH_TO_PRIVATE_DB --tests-passing TEST_COUNT
python scripts/build_site.py
```

Run a secret/PII review before publication. Do not commit credentials, local
paths, private investigation data, or API responses.

## Disclaimer

This is an independent research portfolio and is not affiliated with
ChainBounty. Address attribution is based on publicly available incident
intelligence and reproducible blockchain evidence. On-chain validation confirms
transaction facts and address relationships; it does not constitute a legal
determination of criminal liability. Final attribution may require additional
off-chain evidence and lawful investigative process.
