# Capability matrix

| Capability | Phase 1 status | External requirement |
| --- | --- | --- |
| Offline fixture assessment | Working | None |
| Scope and authorization validation | Working for single public IP live target | None |
| Nmap parser and adapter | Implemented; CLI syntax smoke tested on localhost | Nmap binary for live use |
| Nuclei parser and adapter | Implemented; localhost CLI and JSONL parser smoke tested | Nuclei binary and `REDFORGE_NUCLEI_SAFE_TEMPLATES` |
| Semgrep parser and adapter | Implemented; live execution unverified | Semgrep binary and `REDFORGE_SEMGREP_RULES` |
| Trivy parser and adapter | Implemented; live execution unverified | Trivy binary and local vulnerability database |
| HTML and JSON reports | Working | None |
| PDF reports | Optional, verified locally | `pip install -e '.[pdf]'` |
| Read only authenticated API | Working | `REDFORGE_API_TOKENS` |
| PostgreSQL | Configured, not integration tested | PostgreSQL and `psycopg` |
| ZAP, Greenbone, Subfinder, HTTPX | Planned | Separate tools and configuration |
| SQLmap, MobSF, Burp import | Planned | Separate approval and integrations |
| Dashboard, queue, cancellation, reviewer workflow, SARIF | Planned | Phase 2–4 work |

The offline fixture findings are synthetic. A successful fixture run does not demonstrate scanner coverage against a real target.
