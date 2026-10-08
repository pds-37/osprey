# Phase 9 — Adversarial Security Audit

**Status: COMPLETE — no unresolved P0/P1 found in this audit.** This is a bounded code and regression audit, not a certification or penetration-test attestation. The repository was already dirty when this audit began; existing Phase 0–8 and Phase 9 work was preserved.

## Scope and method

The audit follows the request path from the CLI and frontend through FastAPI routes, shared Osprey scanner/analyzers, evidence and risk engines, remediation workflow, and SQLite persistence. It also inventories test suites, configured external intelligence and optional model-provider calls. Findings are recorded only when supported by code inspection or a reproducible test. No real workspace dependency files are to be changed during the audit.

The main reviewed areas are `osprey/src/osprey`, `backend/guardianos/api`, `backend/guardianos/{core,inventory,intel,risk,remediation,ai,storage}`, the frontend API client, and the Python test suites. Test fixtures and the final workspace scan must use temporary or read-only data and an isolated offline advisory cache.

## Attack surface and trust boundaries

| Surface | Untrusted input / privilege | Existing controls observed | Audit focus |
|---|---|---|---|
| FastAPI public routes | HTTP bodies, query/path IDs, bearer tokens | JWT signature/expiry, configured-user check, RBAC router, 10 MiB body middleware | Every route's scope, object ownership, validation, error leakage |
| Authentication/configuration | passwords, `AUTH_USERS_JSON`, signing key | PBKDF2-HMAC-SHA256, configured production key length, current account checked on every token use | password size/CPU bounds, token claims, defaults |
| SBOM and local scan APIs | attacker-controlled JSON/filesystem path | request byte cap, safe YAML/JSON parsing, workspace-root check | parser exhaustion, symlink/reparse traversal, global destructive operations |
| Osprey workspace scanner | repository manifests, lockfiles, source, config, symlinks | source limits (2,000 files/20 MiB, 1 MiB/file), manifest limits, depth/ignored-dir limits, Tree-sitter node caps for JS/TS and Go, no code execution | Windows file-link availability and parser wall-clock bounds |
| Dependency intelligence | remote OSV/EPSS/KEV responses, local cache | HTTP timeouts, optional offline mode, advisory source provenance, explicit unknown values | response bounds, malformed feeds, cache integrity |
| Evidence and SQLite | evidence payloads, record IDs, database file | canonical JSON, content-addressed IDs, SHA-256 record hash, parameterized SQL, SQLite lock/WAL | tampering, link ownership, concurrency, unbounded record growth |
| Risk/reachability | advisory metadata, submitted source bundle, static parser output | shared deterministic risk engine, bounded submitted-source bundle, static/runtime distinction, Tree-sitter safety limits | coercion, unknown propagation, adversarial source, denial of service |
| Runtime observations | process-local Python probe input | opt-in collector and evidence validation/freshness checks | no implicit process attach or project launch; stale/future evidence |
| Remediation | proposal IDs, approval, manifest/lock hashes, paths | explicit admin approval, workspace root, content hashes, atomic SQLite APPLYING claim, narrow npm files, no npm execution, rollback verification | process-crash partial pair writes; no per-organization workspace map |
| Copilot | question, repository/advisory text, optional model response | bounded structured context, read-only selector, verified evidence IDs, fallback, per-user rate cap | prompt injection, cross-org lookup, provider timeout/output cap, audit data |
| CLI | user paths, options, output paths, SQLite/cache | explicit commands, no automatic project execution | overwrite/symlink output paths, malformed config, exception surfaces |
| Frontend | API responses and bearer token | API client and server-side authentication | browser storage and display of deterministic versus contextual claims |

## Architecture map

- **Shared scanner and engine:** `osprey/src/osprey/scanner.py`, `analyzers/source.py`, `analyzers/reachability.py`, parsers, `risk.py`, `runtime.py`, `remediation.py`, evidence/provenance modules.
- **Backend/API:** `backend/guardianos/api/app.py`, `api/security.py`, `api/v1/*`; inventory, intelligence, risk, graph, exposure, remediation, AI, and storage services under `backend/guardianos`.
- **Persistence:** local SQLite JSON-document store (`storage/sqlite.py`), separate evidence records (`storage/evidence.py`) and audit-event table. SQLite is a local single-instance store; row writes use a process lock, not a distributed transaction or immutable ledger.
- **CLI:** `osprey/src/osprey/cli.py`, invoking the shared scanner and the explicit proposal/apply functionality.
- **Frontend:** React application calling the backend API. Frontend filtering is not an authorization control.
- **External intelligence/model traffic:** Osprey OSV/EPSS/KEV HTTP clients and an opt-in OpenAI-compatible Copilot selector. The selector can choose supplied fact/next-step keys; deterministic code renders returned claims.

## Existing controls observed

- Authentication uses signed HS256 tokens and compares role/organization claims with the currently configured account. Production refuses a missing or short signing key. Password hashes use salted PBKDF2-HMAC-SHA256.
- Protected routers require a viewer for reads and engineer/admin roles for mutations; remediation has explicit admin checks for approval/apply.
- Request bodies, Copilot question/context/provider response, source bundles, source-file count/bytes, and Tree-sitter AST traversal have configured bounds.
- Workspace scans parse without importing or executing target code. Osprey's normal workspace scanner requests are offline in the backend remediation workflow.
- Evidence IDs are based on stable canonical JSON and SHA-256. Record-envelope verification detects modification when the hash/identity no longer matches; SQLite itself remains mutable.
- Runtime states remain distinct and unknown in absence of verified observation. Static reachability is separately stored.
- Remediation is explicit, checks input hashes, restricts supported file types and does not run npm or lifecycle scripts. Rollback is attempted and reported only as verified after hash comparison.
- Copilot does not get shell/filesystem tools. It can only select bounded Osprey-authored fact keys; malformed provider output falls back to deterministic evidence-only output.

## Threat model

| Actor | Capability / likely attack | Impact | Existing mitigation | Gap under audit | Initial severity |
|---|---|---|---|---|---|
| Malicious repository author | Crafted manifests, source, config, symlinks, deeply nested syntax | Local file disclosure, false analysis, CPU/memory exhaustion | Bounded reads, no code execution, reparse-point walk, AST limits, malformed manifest limitations | Parser work has byte/node limits but no in-process wall-clock cancellation | P2 residual |
| Malicious dependency | Poisoned package metadata or source-like strings | Parser confusion, resource pressure, misleading evidence | Data parsed as text; no dependency install | Oversized metadata/recursive structures and unsupported grammar behavior | P2 |
| Malicious advisory/feed | Fake ranges/severity, oversized descriptions, malformed JSON | Incorrect finding/risk or resource exhaustion | Typed models, provenance, offline cache option, unknown defaults | Feed response/cache trust and byte bounds | P2 |
| Malicious authenticated user | Direct object-ID substitution, cross-org reads, cross-workspace path selection, destructive endpoint use | Cross-organization disclosure, workspace analysis, or state change | Authenticated router policy; object org/owner checks; global endpoints and local-workspace operations fail closed in multi-org mode | Multi-org workspace use is unavailable until explicit per-org roots exist | P1 path-boundary defect fixed; remaining use is disabled |
| Unauthorized user | Call API without/with invalid/expired token | Data access or state change | Router-level auth and current-user validation | Check every public route and direct object reference | P1 if a protected route is exposed |
| Compromised model provider | Return fabricated IDs/statuses, injection, oversized response, timeout | Incorrect security explanation or data exposure | Restricted selection schema, bounded context/response, deterministic renderer | Provider egress/configuration, timeout/error handling, regression coverage | P2 |
| Malicious source/advisory content | Indirect prompt injection and fake authoritative fields | Copilot may make unsupported claims | Free text treated as untrusted; context builder validates structured fields | Verify every returned claim remains Osprey-authored and linked | P2 |
| Malicious package metadata | Fake installed versions/paths or malicious package names | Inventory/risk poisoning, path confusion | Pydantic validation and package parsers | Canonical identity validation and bounds across formats | P2 |
| Local attacker | Replace workspace files/links during scan/apply or target outside root | Unauthorized file read/write or stale apply | Canonical-root containment, reparse-point skip, no-follow bounded reads, hash checks, atomic proposal claim | Concurrent hostile filesystem replacement is not a cross-platform transactional guarantee | P2 residual |
| Denial-of-service attacker | Large API body, many files/records, pathological input/provider | CPU/memory/disk exhaustion | Body/context/source/AST limits and provider timeout | Limits on manifest files/lockfiles, persistent record counts, per-user request surfaces | P2 |

## Findings and fixes

### P1 — Workspace path selection crossed organization boundaries — FIXED

**Attack:** a user in one configured organization could choose another organization's subdirectory under the shared `WORKSPACE_ROOT` in local-scan or remediation requests. Path containment alone did not establish tenant ownership because no per-organization workspace registry existed.

**Impact:** unauthorized source analysis and creation of a remediation proposal against files in another tenant's workspace; this was not an arbitrary filesystem escape outside the configured root.

**Fix:** local workspace scanning, remediation proposal creation, and remediation apply now return 409 in multi-organization mode. This fails closed until the deployment has explicit per-organization workspace roots. Object ID substitution continues to return 404 across organizations.

**Regression tests:** `tests/security/test_organization_isolation.py::test_local_workspace_scan_and_remediation_fail_closed_for_multiple_organizations`, plus finding/component/evidence/Copilot cross-org tests.

### P2 — Finding evidence linked through a remediation workflow was inaccessible — FIXED

The evidence endpoint checked a workflow's remediation-event IDs but omitted `finding_evidence_ids`, so legitimate callers received 404 for evidence returned by proposal creation. The ownership check now recognizes both lists only when the workflow organization matches. Cross-organization substitution remains 404.

**Regression tests:** `tests/security/test_organization_isolation.py::test_remediation_finding_evidence_is_owner_org_scoped` and the end-to-end proposal/evidence test.

### P2 — Malformed dependency manifests could look like an empty inventory or crash parsing — FIXED

Malformed npm JSON previously returned an empty component list without a scan limitation; wrong-shaped valid JSON could raise during extraction. Malformed Python TOML and Compose YAML had similar swallowed-error paths. Supported parser failures and malformed shapes now surface generic bounded limitations; npm section-shape errors fail closed.

**Regression tests:** malformed npm JSON/root/section cases and malformed TOML/Compose YAML cases in `tests/security/test_scanner_filesystem.py`.

### P2 — Lone Unicode surrogates could raise during evidence hashing — FIXED

`analyze_source_files` now rejects invalid Unicode source before evidence creation and records a limitation, rather than allowing a `UnicodeEncodeError` to escape.

**Regression test:** `tests/security/test_parser_safety.py::test_unpaired_surrogate_is_rejected_before_evidence_hashing`.

### P2 — Oversized advisory numbers could abort risk calculation — FIXED

Converting a sufficiently large integer CVSS/EPSS value to float raised `OverflowError`. The shared deterministic risk normalizer now treats conversion failures as unavailable, preserving `UNKNOWN` and an explicit limitation. NaN, Infinity, booleans, strings, and out-of-range numbers are also rejected.

**Regression tests:** `tests/security/test_risk_inputs.py` (15 cases).

### P2 — Go AST traversal lacked the Tree-sitter node ceiling — FIXED

Go parsing now skips analysis with a clear limitation when traversal exceeds 4,096 AST nodes, matching the existing JavaScript/TypeScript bound.

**Regression test:** `tests/security/test_parser_safety.py::test_pathological_go_returns_ast_limit_instead_of_unbounded_walk`.

### P2 — Concurrent remediation requests could race a replay check — FIXED

Each request previously checked a process-local workflow snapshot before saving `APPLYING`; simultaneous applies could both pass that check. SQLite now atomically claims `APPROVED → APPLYING` with `BEGIN IMMEDIATE` and a conditional state update before file application.

**Regression test:** `tests/integration/test_remediation_workflow_api.py::test_concurrent_apply_claims_proposal_once` synchronizes two applies after their pre-apply scans and verifies exactly one claim succeeds.

### Findings checked and not reproduced

- Direct cross-organization finding, component, evidence, proposal, and Copilot ID substitution is rejected server-side by existing tests.
- Workspace `../`, drive, UNC, and resolved symlink escape attempts are rejected. Scanner tests show directory-junction entries are skipped. The file-symlink regression test was skipped because file symlinks were unavailable on this host.
- Global legacy operations fail closed for multiple organizations. Clear-existing is refused rather than used to clear shared tenant state.
- Evidence records detect payload/envelope tampering, but SQLite can still be edited by a local operator; this is tamper-evident, not immutable.
- Parser probes for truncated JS/TS/TSX, malformed Go/Python, deep syntax, large ASTs, null/Unicode text, and surrogate input completed without a native crash after the fixes.

## Security assumptions and limitations

- The current backend is a local SQLite application. Individual remediation claims use a SQLite transaction, but this is not a supported clustered deployment or a general distributed workflow transaction. SQLite's evidence rows remain editable by a local operator and are tamper-evident only when verified, not immutable or tamper-proof.
- Multiple configured organizations cannot use local workspace scan or remediation until an explicit per-organization workspace mapping is implemented. This is an intentional fail-closed limitation.
- Applying a manifest and lockfile requires two filesystem replacements. Rollback is attempted and hash-verified after ordinary failures; abrupt process termination between replacements cannot be made atomic across both files.
- The optional remote Copilot provider receives a bounded finding context and question. It must be treated as a third-party data recipient; the endpoint remains read-only, but deployments must decide whether remote provider use is acceptable.
- Static source parsing and reachability are syntax-level approximations. Unsupported syntax, parser recovery, dynamic dispatch, and traversal limits remain UNKNOWN/limitations, not proof of safety.
- Runtime evidence is process-local and environment-specific. It does not establish production exposure, exploitability, or absence of a vulnerability.
- Windows reparse-point behavior depends on the filesystem and Python runtime; if it cannot be safely enumerated, the scanner must report/skip it rather than follow it.
- Tree-sitter input bytes and AST traversal are bounded, and recovered syntax is skipped. The parser call itself has no configured wall-clock cancellation; the adversarial probes were isolated in subprocesses with timeouts.
- Static risk/reachability, parser support, API behavior, and Copilot mocks were tested. A production remote model provider was not configured, and no frontend browser/component test suite exists.
- Dependency declarations and lockfiles were inspected, and `pip check` passed. No vulnerability-feed audit tool (`pip-audit`/`safety`) is installed; current package CVE status was not certified, and dependency versions were not changed.

## Final verification (2026-10-09)

- Backend/API/security full suite: **148 passed, 1 skipped** (149 collected); the one skip is the host-dependent file-symlink test. One Starlette/httpx deprecation warning was emitted.
- Standalone Osprey CLI/shared scanner suite: **140 passed**.
- Focused security selection: **41 passed, 1 skipped** across filesystem, parser, organization isolation, risk inputs, remediation workflow, and SQLite persistence tests.
- Frontend TypeScript/Vite production build: **passed**; no frontend automated suite is configured.
- Dependency consistency: `pip check` — **no broken requirements**. No packages were changed.
- Final Osprey scan: 171 source files, 1,087 call edges (382 inter-file), 233 components, zero findings, zero runtime observations, 686 limitations, zero file-read limitations, 4 parser-recovery limitations, 1 AST-limit event, zero crashes. The isolated offline cache reported `UNAVAILABLE` for all 233 components; zero findings does not mean zero vulnerabilities.

## Phase 9 work log

The final scan used the verified repository root and an isolated cache under the Codex task's `work/` directory. It did not modify repository manifests, lockfiles, or source files.
