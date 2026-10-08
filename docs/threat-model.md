# Threat Model

**Scope:** Osprey CLI, FastAPI service, local SQLite state, and React dashboard.

## Assets

- Source and dependency metadata supplied for analysis.
- Vulnerability findings and their evidence references.
- Configured user credentials, JWT signing key, and administrative actions.
- Local SQLite inventory, evidence, remediation, and audit records.

Osprey does not currently hold cloud credentials or connect to production workloads as part of the supported analysis path.

## Trust boundaries and untrusted inputs

- Repository manifests, lockfiles, source code, and SBOMs are untrusted input. Scanning reads text; it does not import or execute target code.
- OSV, EPSS, CISA, and user-submitted advisory/commit data are external/untrusted data, not instructions.
- The local workspace scanner is restricted to a configured root. Reachability accepts a size-bounded map of relative paths and source text.
- API users are authenticated from `AUTH_USERS_JSON`; JWT role claims are checked against current configured user/role data.
- Local filesystem and SQLite administrators are trusted operators. SQLite audit records are not tamper-proof against them.

## Threats and controls

| Threat | Current control | Residual limit |
|---|---|---|
| Unauthenticated API mutation | Bearer JWT required; viewer, security_engineer, admin role checks | No OIDC/SSO, refresh tokens, user-management API, or rate limiting. |
| Unauthorized approval/configuration | Admin role; approval actor taken from authenticated identity | Approval is a workflow record, not a Git or deployment action. |
| Credential or signing-key exposure | PBKDF2-SHA256 password hashes; no default production signing key; minimum 32-byte secret | Key rotation and secret-manager integration are operational responsibilities. |
| Oversized request or SBOM | ASGI request body limit and bounded file read | CPU, concurrent request, and per-user rate limits are not implemented. |
| Path traversal during workspace scan | Resolved target must remain under `WORKSPACE_ROOT` or working directory | Deployment should still mount only intended directories and run with least filesystem privilege. |
| Malicious source/advisory content | Static parsers; no execution; bounded input; deterministic analyzer does not treat text as instructions | Parser bugs and resource exhaustion remain possible; use process/container isolation for hostile repositories. |
| False reachability/exposure claim | Conservative `REACHABLE` / `NOT_REACHABLE` / `UNKNOWN`; source route is not external ingress | Cross-file, reflection, dynamic loading, and framework semantics are incomplete. |
| Forged runtime/production state | SBOM cannot set `RUNNING`; local inspection distinguishes lockfile resolution from installation; Python runtime evidence requires an already-loaded module and explicit caller instrumentation. Labels are metadata, runtime evidence is freshness-bounded, and missing evidence remains `UNKNOWN`. | Runtime evidence is specific to the observed process/environment and does not prove production presence or exploitability. Manual endpoint assertions remain user-supplied assertions and must be labeled accordingly. |
| Audit tampering | Audit records are persisted in SQLite and appended through service API | A local DB owner can edit or delete the file; not an immutable ledger. |
| Demo data mistaken for production | Demo endpoint is role-protected and requires the fixture flag; UI marks it simulated | Operators must not export fixture values as real findings. |

## Authentication and roles

- `viewer`: read-only APIs.
- `security_engineer`: analysis and inventory ingestion.
- `admin`: remediation approval and inventory clearing.

Users are configuration-managed. Production requires a configured `SECRET_KEY`; development may use a process-local random key, which invalidates tokens after restart.

## Evidence policy

Each conclusion is bounded by its source. A manifest proves declared intent; an SBOM proves what its producer reported; source parsing proves only selected syntax; user endpoint configuration is not discovered ingress. No source analyzer can establish deployment, cloud IAM, external routing, or runtime state without a corresponding collector.
