# Osprey Release Candidate

**Product:** Osprey - Evidence-Driven Software Supply Chain Security
**Release posture:** Release candidate; not a production-service security certification.

Osprey combines dependency inventory and vulnerability intelligence with bounded symbol and static reachability analysis, local runtime/install observations, deterministic risk, provenance-bearing evidence, approval-gated remediation, verification, and an evidence-grounded read-only Copilot.

## Current capabilities

- Dependency inventory from supported manifests, lockfiles, and SBOM formats; OSV version matching.
- Vulnerable-symbol mapping when advisory metadata supports it.
- Bounded static reachability for supported syntax; results may be REACHABLE, NOT_REACHABLE, or UNKNOWN.
- Local runtime/install observations kept distinct from static reachability.
- Deterministic risk calculation with explicit unknowns.
- Provenance-bearing evidence with integrity hashes. SQLite remains mutable; validation is tamper-evident, not immutable.
- Explicitly approved, constrained remediation proposals and scoped verification.
- Read-only Copilot grounded in Osprey-validated records. An optional remote provider is an external data recipient.
- Adversarial hardening and regression coverage documented in [Phase 9](SECURITY_AUDIT_PHASE9.md).

## Security posture

Phase 9 recorded **COMPLETE** with no unresolved P0/P1 findings in its bounded code and regression audit. This is not a penetration-test attestation. Tested controls include server-side role/organization and object-ownership checks, fail-closed workspace behavior for ambiguous multi-organization setups, bounded parsing/requests, evidence hash validation, deterministic risk, and approval-gated remediation that does not execute npm or project commands.

Residual boundaries: SQLite is local and mutable; two remediation file replacements cannot be atomic as a pair across process termination; Tree-sitter traversal is bounded but has no parser wall-clock cancellation; file-symlink tests were unavailable on this Windows host; there is no browser regression suite or production runtime telemetry; optional remote model use sends bounded context to a provider.

## Dependency posture (Phase 11)

The frontend audit initially reported 9 issues (3 moderate, 6 high). Vite was upgraded from 5.4.21 to 6.4.4 after a scratch compatibility build passed. The final lockfile audit reports **7 issues: 2 moderate, 5 high, 0 critical**, all in Tailwind CSS and its development/build-time tree. A normal npm audit fix does not resolve these. npm proposes Tailwind CSS 4.3.3, a major version migration; it was not applied without compatibility review.

| Package | Locked version | Severity | Directness | Class | Affected range / fixed path |
|---|---:|---|---|---|
| tailwindcss | 3.4.19 | High | Direct dev | B, D | Affected through 3.4.19; fixed path reported by npm is 4.3.3 (major). |
| braces | 3.0.3 | High | Transitive | C, D | GHSA-vfj7-8cjw-p6xm, <=3.0.3; registry latest is 3.0.3, so no fixed braces release was available. npm's fix path is Tailwind 4.3.3. |
| chokidar | 3.6.0 | High | Transitive | C, D | Affected through 3.6.0; newer major line 5.0.0 exists, but Tailwind's applicable npm fix is 4.3.3. |
| micromatch | 4.0.8 | High | Transitive | C, D | The registry latest remains 4.0.8; affected through vulnerable braces. npm's fix path is Tailwind 4.3.3. |
| fast-glob | 3.3.3 | High | Transitive | C, D | Registry latest remains 3.3.3; npm reports affected via micromatch. No compatible non-force fix; npm proposes Tailwind 4.3.3. |
| postcss-selector-parser | 6.1.4 | Moderate | Transitive | C, D | GHSA-rj75-hqrm-r3gf, <7.1.6; 7.1.6 is fixed, but compatible non-force audit fix did not resolve Tailwind's dependency tree. |
| postcss-nested | 6.2.0 | Moderate | Transitive | C, D | Affected through postcss-selector-parser (2.0.3-6.2.0). |

Class meanings: B = requires compatibility review because the direct Tailwind fix is a major upgrade; C = transitive advisory without a compatible safe fix through the current dependency graph; D = development/build-time exposure. No advisory was classified as a false positive.

These are development/build-time dependencies, not packages declared under frontend runtime dependencies. They still matter when developers run the dev server or build untrusted repository content. Vite/esbuild findings were cleared by the tested Vite upgrade. Running npm audit fix in a scratch copy left 7 issues and reported Tailwind 4.3.3 as a breaking change. Do not suppress advisories; reassess during a reviewed Tailwind 4 migration.

Python constraints are ranges in osprey/pyproject.toml and backend/requirements.txt; there is no Python lockfile. A clean Python 3.14 venv installed both sets and passed pip check and both suites. This demonstrates installability on this host, not byte-for-byte reproducibility. pip-audit and safety were unavailable, so Python CVE coverage is **not assessed**.

## Reproducible verification

Windows PowerShell commands from the repository root:

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -e .\osprey
    python -m pip install -r .\backend\requirements.txt
    Push-Location .\frontend
    npm ci --ignore-scripts
    npm run build
    Pop-Location
    .\verify.ps1

npm ci --ignore-scripts and the production build were verified in a clean temporary copy using the committed lockfile; lifecycle scripts were disabled. The Python install and both suites passed in a disposable venv; backend startup and CLI entry point were smoke-tested there. verify.ps1 runs backend/API tests, shared Osprey tests, pip check, TypeScript validation, and production build.

Run the offline demo with python .\osprey\examples\phase10-offline-demo\run_demo.py; type APPROVE only after reviewing its temporary two-file proposal. It uses synthetic advisory data and does not install dependencies or execute analyzed code.

## Versions

There is no single project-wide release version. Current metadata: frontend 2.0.0, backend APP_VERSION 0.2.0, Python distribution osprey-sc 0.1.0. Repository branding/history refers to Osprey 2.0. A future unified presentation label could be Osprey 2.0.0, but no unified version was applied because the component versions are not aligned. Do not present the component versions as a unified release tag.

## Phase 11 verification (2026-10-09)

- Full repository verification: backend/API 148 passed, 1 skipped (149 collected); shared Osprey CLI/scanner 141 passed; pip check clean; frontend TypeScript and production build passed.
- Dedicated security suite: 33 passed, 1 skipped (34 collected). The skip is the host-dependent file-symlink test. A Starlette/httpx deprecation warning remains.
- Clean disposable Python 3.14 environment: editable Osprey and backend requirements installed; backend/API 148 passed, 1 skipped; shared suite 141 passed; pip check clean; CLI help worked; backend /health returned HTTP 200 using temporary SQLite state.
- Clean temporary frontend copy: npm ci --ignore-scripts and production build passed on Vite 6.4.4; npm reported 7 advisories (2 moderate, 5 high, 0 critical).
- Offline deterministic demo: explicit approval applied only the temporary manifest/lock pair and the rescan returned VERIFIED. Risk and runtime remained UNKNOWN; this is narrow fixture verification.
- Final read-only scan: 175 source files, 240 components, 1,096 call edges (389 inter-file), 0 findings, 175 installation observations, 0 runtime-execution observations, 690 limitations, 4 parser-recovery limitations, 1 AST-limit event, no crashes, 3.622 seconds. An isolated empty offline cache reported advisory coverage UNAVAILABLE for all 240 components; zero findings is not evidence of zero vulnerabilities.
- Final git diff --check passed. The worktree remains dirty from pre-existing Phase 0–10 work plus the Phase 11 dependency/docs changes; no commit or tag was made.

## License metadata assessment

The repository-root LICENSE now matches the existing MIT text in osprey/LICENSE, and the Python distribution declares MIT. The frontend package remains marked private and has no license field. The package lockfile contains license metadata for all 187 locked package entries inspected. This is a metadata review only, not a full license compatibility or legal-compliance audit.

## Known limitations

- Advisory coverage depends on source/cache state; unavailable coverage means zero findings is not evidence of zero vulnerabilities.
- Static reachability is bounded and syntax-based; it does not prove exploitability or complete call behavior.
- Runtime observations are local and bounded, not production telemetry or proof of deployment exposure.
- SQLite is local and mutable, not distributed or immutable.
- No browser automation/regression suite is configured.
- Python dependencies are not locked and no Python audit tool was available.
- Seven npm development-dependency advisories remain (2 moderate, 5 high) pending a reviewed Tailwind migration.
- The ignored root .env has a non-empty GEMINI_API_KEY. Its value was not displayed or validated. Keep it out of release artifacts; verify/rotate it locally if it is a real credential.
- Windows application control blocked generated osprey.exe in this audit. The CLI entry function worked through Python; behavior under other policies was not established.

## Release recommendation

**RELEASE CANDIDATE** for a scoped portfolio/reviewer release after pre-existing worktree changes are reviewed and staged intentionally. Do not present this as a production-ready hosted service or claim all advisories are resolved. The worktree is not clean and was not committed or tagged.
