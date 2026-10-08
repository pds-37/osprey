# Verified Project Status

**Snapshot:** 2026-10-09
**Repository:** Osprey Git checkout (local machine path intentionally omitted)
**Branch:** `main`
**HEAD:** `280edc6` (`chore(branding): update html page title to Osprey`)

This report separates the committed baseline from the working tree. The checkout was already substantially modified before this Phase 10 work. Those changes are preserved and are not attributed to Phase 10 without commit-level evidence.

## Git baseline

The requested baseline commands were run:

- `git status --short`: 100 tracked paths changed/deleted/renamed plus numerous untracked paths, including backend/API changes, the shared `osprey/` package, tests, and Phase 9 documentation.
- `git branch --show-current`: `main`.
- `git log -10 --oneline`: HEAD and recent Phase 8, Phase 9, and Phase 10 commits are listed below.
- `git diff --stat`: 100 tracked paths; 4,734 insertions and 2,605 deletions at baseline.
- `git rev-parse --show-toplevel`: exact repository root stated above.

Recent committed history:

```text
280edc6 chore(branding): update html page title to Osprey
3fc475c fix(scanner): smart directory resolution, parallel OSV queries, demo clearing, and rich error diagnostics
1a67513 feat(osprey): release Osprey v2.0 - plug-and-play supply chain attack path control plane
79f9fcd feat(landing): add public viral landing page highlighting the .HEIC ChatGPT incident
e0d1700 feat(ui): implement clean 3-workspace architecture and slide-over AI Copilot drawer
5e3e05f feat(ui): redesign complete frontend with full dark black minimalist aesthetics
2cfa33f fix(vite): add /health proxy target to vite dev config
160e2c8 feat(phase-10): complete UI control plane & flagship end-to-end demo walkthrough
9eab24a feat(phase-9): implement remediation engine, PR generation, human approval, and verification rescan
b4a251f feat(phase-8): implement evidence-grounded AI security analyst with tool invocation and injection defense
```

## Project map

| Area | Location | Verified role |
|---|---|---|
| Shared engine and CLI | `osprey/src/osprey/` | Manifest/SBOM inventory, OSV cache/client, source parsing, reachability, evidence, risk, runtime observations, remediation helper, CLI |
| API/backend | `backend/guardianos/` | FastAPI routes, configured bearer authentication and roles, inventory/advisory adapters, evidence and SQLite persistence, risk, remediation workflow, Copilot |
| Frontend | `frontend/` | React/Vite UI using the API; production build is the available automated UI check |
| Tests | `tests/`, `osprey/tests/` | Backend/API and shared engine/CLI regression suites |
| Documentation | `docs/` | Architecture, API, threat/security boundaries, evidence, reachability, runtime, remediation, audit, tests |

## Committed, uncommitted, and phase attribution

The last ten commits include features named Phase 8, Phase 9, and Phase 10; current `HEAD` is later branding. The Phase 9/Phase 10 audits take place on top of this history and a dirty worktree. At baseline, changes included code, tests, docs, a case-only architecture-document rename, removal of legacy AI vector-store code, a frontend component deletion, and untracked shared-engine/backend files. Most of this is uncommitted and cannot be reliably assigned to one phase from `git status` alone. The earlier-phase commit history is retained unchanged. This Phase 10 task does not reset, clean, checkout, or commit.

The exact detailed path list is available from `git status --short`; see the final Phase 10 Git report for the post-task delta. `.phase9-pytest-tmp/` was already untracked at the baseline and is preserved.

## Generated files, secrets, and dependencies

- The tracked frontend lockfile is `frontend/package-lock.json`. `frontend/dist/`, `frontend/node_modules/`, Python caches, `.venv/`, SQLite state, and logs are ignored by `.gitignore`; no generated build directory was tracked in the inspected status. The untracked Osprey tree includes a 2026-10-04 SQLite advisory-cache fixture under `osprey/tests/fixtures/cache/`, described as public OSV/EPSS/KEV metadata; it is not a generated build output and is not tracked at this baseline.
- `.env` is ignored. It was not present as a tracked Git path. Secret scanning covered tracked and untracked source/text files and found no credential patterns; local environment files were not printed or copied into this report.
- Python dependencies are declared with lower bounds/ranges in `backend/requirements.txt` and `osprey/pyproject.toml`; there is no Python lockfile. The frontend has a tracked npm lockfile. This means Python installs are not fully version-reproducible.
- `pip check` passed in the current environment. `pip-audit` and `safety` were not installed, so this snapshot does not claim a comprehensive current dependency vulnerability audit.

## Verified behavior and limits

The 2026-10-09 Phase 9 verification recorded 148 passed and 1 skipped backend/API tests, 140 passed shared Osprey tests, a successful frontend production build, and successful `pip check`. The offline source scan analyzed 171 source files, 233 components, 1,087 call edges (382 inter-file), 0 findings, 0 runtime observations, and 686 limitations. Advisory coverage was unavailable for all 233 components; the empty finding set is not evidence of no vulnerabilities. Full detail and qualifications are in [SECURITY_AUDIT_PHASE9.md](SECURITY_AUDIT_PHASE9.md).

At the beginning of Phase 10 the available implementation describes a bounded static-analysis subset, local SQLite document persistence, a read-only evidence-grounded Copilot, and explicit approval-gated npm remediation. It does not establish exploitability, public exposure, complete reachability, production runtime state, immutable evidence, autonomous remediation, or enterprise multi-tenancy.

## Phase 10 final verification snapshot

- Complete documented verification: backend/API **148 passed, 1 skipped**; shared Osprey/CLI **141 passed**; `pip check` clean; frontend TypeScript and Vite production build passed.
- Offline demo ran with explicit approval on a temporary copy: synthetic advisory finding, static reachability, deterministic risk `UNKNOWN` where inputs were deliberately absent, exact two-file proposal, apply, and scoped `VERIFIED` post-scan. No npm process ran.
- OpenAPI route cross-check: 53 actual routes, all 53 documented.
- Backend startup smoke test: README command ran on loopback using a temporary SQLite path and synthetic key; `/health` and `/ready` returned 200.
- Final read-only scan against this repository: 175 source files, 237 components, 1,096 call edges (389 inter-file), 0 findings, 0 runtime observations, 690 parser/analyzer limitations, 4 parser recovery limitations, 1 AST-limit event, and no crash. Advisory coverage was `UNAVAILABLE` for all 237 components. The zero-finding result is not an absence-of-vulnerabilities claim.
- Scan performance: 3.633 seconds uninstrumented; a separate `tracemalloc` run took 25.789 seconds and observed 13.16 MiB peak Python-traced allocations. The traced-memory figure excludes native Tree-sitter allocations and tracing increases elapsed time; neither run is a production benchmark.
- Frontend now warns when protected data failed to load and clears organization-bound client state at sign-out. The SQLite cache closes connections after each operation; a regression test checks that the database can be moved immediately after use on Windows.
- Dependency reproducibility checks: frontend `npm ci --ignore-scripts` worked from a disposable copy and built successfully; `npm audit` reported 9 development dependency advisories (3 moderate, 6 high, 0 critical), including direct Vite and Tailwind entries. No versions were changed because suggested fixes cross major lines. Python requirements remain range-based without a lockfile; `pip check` passed, but no full Python CVE audit tool was available.
