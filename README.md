# RedForge VAPT Engine

Phase 1 local foundation for authorized, policy controlled VAPT assessment. The offline demo makes no network requests and needs no scanner binary or AI service.

## Install and run

Requires Python 3.12 or newer.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/alembic upgrade head
.venv/bin/redforge-vapt doctor
.venv/bin/redforge-vapt scan --config engagements/demo.yaml --profile passive --fixture-dir fixtures/demo --report html,json
.venv/bin/redforge-vapt scans list
```

Reports are written to `reports/`, with raw redacted scanner output in private `artifacts/` subdirectories. Use the returned scan ID with `redforge-vapt scans status ID` or `redforge-vapt report ID --format html`.

`redforge-vapt scan --dry-run --config engagements/demo.yaml --fixture-dir fixtures/demo` validates and shows an offline plan. A real scan requires a different engagement config with explicit authorization acknowledgement, an approved profile, a current testing window, scoped public targets, and per scanner permission for network tools. `passive` permits only offline source analysis. `safe-active` permits bounded Nmap and curated Nuclei checks. Localhost and private IPs are blocked for live execution. Never use the demo config as evidence of an actual assessment.

For API access, set `REDFORGE_API_TOKENS` to a JSON map of bearer tokens to users, for example `{"long-random-token":{"role":"reviewer","engagements":["demo-local-001"]}}`. Then run `redforge-vapt serve`. The API currently exposes read only scan, tool, and report endpoints. Bind to localhost or put behind an authenticated TLS reverse proxy.

## Status

Nmap, Nuclei, Semgrep, and Trivy have machine-readable parsers and CLI adapters. Nmap and Nuclei require their binaries; Semgrep and Trivy require theirs and local source configuration. Nuclei live mode additionally requires a vetted local template directory in `REDFORGE_NUCLEI_SAFE_TEMPLATES`. Semgrep requires a local rules file in `REDFORGE_SEMGREP_RULES` so no remote rule lookup occurs. Phase 1 network scans require a public IP literal and exactly one target. No scanners are bundled in the image. ZAP, Greenbone, Subfinder, HTTPX, SQLmap, MobSF, and Burp manual import are planned, not integrated. PDF is optional (`pip install -e '.[pdf]'`).

This is a Phase 1 foundation. It does not include the full web dashboard, queue, cancellation, reviewer workflow, SARIF, or all requested scanners. See [SECURITY.md](SECURITY.md) for safety constraints, the [operator guide](docs/operator-guide.md) for execution, and the [capability matrix](docs/capabilities.md) for current support.
