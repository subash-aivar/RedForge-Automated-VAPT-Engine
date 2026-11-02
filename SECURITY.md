# Security model and limitations

- Live scanning requires written engagement authorization represented by the config acknowledgement, approved profile, testing window, exact scope, and scanner permission. The engine treats this acknowledgement as an operator attestation, not proof of legal authorization.
- Only public IP addresses resolve for live targets. Internal, loopback, link local, and metadata addresses are blocked. The offline fixture mode bypasses live resolution and runs no scanner binaries.
- Passive mode does not run network scanners. Nuclei live mode accepts only a constrained YAML template subset with fixed `{{BaseURL}}` paths and GET/HEAD requests. It disables redirects, OAST, and extra HTTP probing, and uses bounded rate and concurrency settings. Template review remains the operator's responsibility.
- The subprocess runner uses fixed argument lists, timeouts, and bounded output handling. External scanner binaries remain trusted local dependencies; do not install untrusted versions.
- Raw output is redacted for common secret fields and written with mode 0600. Redaction is best effort; use dedicated assessment hosts and limit artifact access. Source scan output can contain sensitive code snippets.
- Findings are scanner observations with `unverified` status. The product does not claim exploit confirmation or compliance.
- API tokens are loaded from an environment variable. Store them in a secrets manager or protected environment file; do not commit them. Use TLS for remote access.
- SQLite is intended for local use. PostgreSQL is supported by SQLAlchemy with the `psycopg` driver, but the Compose setup is not yet a hardened production deployment.
