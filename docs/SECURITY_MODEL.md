# Osprey Security Model

**Updated:** 2026-10-09

## Identity and authorization

The FastAPI adapter issues OAuth2-compatible bearer JWTs for accounts configured in `AUTH_USERS_JSON`. Passwords are verified using PBKDF2-SHA256 hashes. JWT role claims are checked against the currently configured account and role before access is granted.

| Role | Allowed actions |
|---|---|
| `viewer` | Read protected inventory and analysis records. |
| `security_engineer` | Viewer actions, ingest SBOMs, scan the configured workspace, analyze reachability, create endpoint assertions, and create remediation recommendations. |
| `admin` | Security engineer actions, approve recommendations, clear inventory, and run the explicitly enabled demo fixture. |

Users are configuration-managed; no user-management API or OIDC integration exists. Production startup requires a signing key of at least 32 bytes. Development may use a process-local random key, which invalidates tokens after restart. The dashboard stores the bearer token in page memory only.

## Trust boundaries

- **Browser to API:** Bearer authentication and role checks protect API operations. The local Compose setup binds ports to loopback; it is not an internet-facing deployment template.
- **SBOM and package metadata to Osprey:** Treat names, descriptions, versions, and relationships as untrusted input. Parsers validate structure but cannot prove a producer is honest.
- **Source bundle to static analyzer:** Source is parsed as text and never executed. Reachability request limits and relative-path checks apply; parser support is incomplete.
- **Workspace to scanner:** Local scans are constrained to the configured workspace root or process working directory and use file filters and size/count limits.
- **External advisory service to Osprey:** OSV responses are external data. They may be unavailable or incomplete; bundled backend records are explicitly labeled fixture/fallback data.
- **Application to SQLite:** Local inventory and evidence metadata persist in SQLite. The database file is mutable by its host owner and is not a tamper-proof audit sink.
- **Demo fixture to normal analysis:** Synthetic demo data is seeded only through an explicit setting and admin-protected action. Fixture paths, propagation records, and associated remediation tasks carry fixture labels; the UI displays a global fixture warning.

## Implemented controls

- JWT authentication, configured-account role checks, and role-protected mutating routes.
- A default 10 MiB ASGI request-body cap and bounded source-analysis requests.
- Safe local workspace path resolution and static-only parsing.
- SQLite persistence for local single-instance use and an append-only application audit table.
- Deterministic evidence creation and read-only evidence summaries; no LLM currently creates findings or evidence.

## Limits and follow-up

Organization checks are implemented for several persisted object paths, including findings, evidence, Copilot context, and remediation workflow ownership. Some legacy/global services use a single-organization guard instead of partitioned persistence. Local scans/remediation fail closed when multiple organizations are configured because there is no per-organization workspace mapping. This is not a general multi-tenant isolation architecture.

There is no OIDC, distributed or multi-process SQLite deployment design, external tamper-resistant audit sink, or production runtime/cloud collector. Copilot rate limiting is per-process. The application does not inspect cloud credentials or deployment state. Compose binds to loopback and is a local single-instance example, not a production deployment template. Use an appropriate reverse proxy, managed secrets, filesystem isolation, backups, and external identity provider before any real deployment; those controls are not supplied by this repository.
