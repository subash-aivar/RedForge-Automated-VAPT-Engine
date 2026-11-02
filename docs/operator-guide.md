# Operator guide

## Offline demonstration

From the repository root, install with `python3 -m venv .venv` and `.venv/bin/pip install -e '.[test,pdf]'`. Run `.venv/bin/alembic upgrade head`, then:

```bash
.venv/bin/redforge-vapt doctor
.venv/bin/redforge-vapt scan --dry-run --config engagements/demo.yaml --profile passive --fixture-dir fixtures/demo
.venv/bin/redforge-vapt scan --config engagements/demo.yaml --profile passive --fixture-dir fixtures/demo --report html,pdf,json
```

The second command prints a scan ID and report paths. `scans list`, `scans status ID`, and `report ID --format html` read the persisted run. The fixture mode never launches scanner binaries. Its results are synthetic and must not be shared as findings from a real assessment.

## Live engagement prerequisites

The current live path is intentionally narrow: exactly one public IP address, a current timezone aware window, acknowledgement of engagement authorization, and the selected profile in `approved_profiles`. `passive` permits local Semgrep/Trivy work. `safe-active` is required for Nmap/Nuclei and each network scanner must have `scanner_permissions` set to true. A `manual` profile is rejected because separate intrusive approval and modules are not implemented.

Review the target address, port list, protocol, exclusions, rate, `max_requests`, concurrency, and timeout before running. Use `--dry-run` first. Nmap requires `tcp` in the allowed protocols; Nuclei requires `http` or `https`. Domain based network scans, CIDR target expansion, localhost/private IP live scans, and out of scope redirects are not supported in this release. The engine rejects them rather than guessing at safe routing. Nuclei additionally needs a local `REDFORGE_NUCLEI_SAFE_TEMPLATES` directory containing only fixed `{{BaseURL}}` GET/HEAD HTTP templates. Semgrep requires a local `REDFORGE_SEMGREP_RULES` file. Trivy requires a local vulnerability database. Never point `source_path` at data outside the engagement.

## Storage and API

SQLite defaults to `./redforge.db`. Set `REDFORGE_DATABASE_URL` for PostgreSQL or another supported SQLAlchemy URL. The first Alembic revision is in `migrations/`. Set `REDFORGE_ARTIFACT_DIR` for private redacted scanner outputs. Reports are placed in `reports/` with mode 0600. Protect these locations and apply a retention policy appropriate to the engagement.

The FastAPI service is read only in this milestone. Set `REDFORGE_API_TOKENS` to a JSON object mapping high entropy bearer tokens to a role and engagement list; `administrator` can read all engagements. Operators and reviewers can read only the listed engagement IDs. Bind the service to localhost or put it behind a TLS reverse proxy. The Compose file expects `REDFORGE_POSTGRES_PASSWORD` and `REDFORGE_API_TOKENS` from a protected environment and binds the API to localhost.
