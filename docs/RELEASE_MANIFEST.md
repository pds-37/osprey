# Osprey Release Manifest

- **Product:** Osprey - Evidence-Driven Software Supply Chain Security
- **Release state:** Portfolio Release Candidate
- **Architecture:** Frozen for this release; no new product capabilities in this pass.
- **Version metadata:** Frontend 2.0.0, backend APP_VERSION 0.2.0, Python package osprey-sc 0.1.0. There is no unified release tag.
- **License:** MIT; repository-root LICENSE matches the existing declared Osprey license text.

## Major capabilities

Dependency inventory and advisory/version matching; vulnerable-symbol mapping when available; bounded static reachability; separate local installation/runtime observations; deterministic evidence-aware risk; provenance-bearing evidence; explicit-approval npm remediation; scoped rescan verification; evidence-grounded read-only Copilot.

## Security audit

**Phase 9 status:** Complete for the bounded audit scope; not a certification.

Phase 9 is recorded complete after a bounded adversarial code/test audit with no unresolved P0/P1 finding reported in that audit. It is not a certification or penetration-test report. SQLite remains mutable and local; static analysis/runtime collection remain bounded.

## Dependency audit

**Phase 11 status:** Complete; advisories and audit-tool limitations are disclosed below.

Phase 11 assessed the npm dependency audit and clean installs. Vite 6.4.4 was applied after a compatibility build. The final npm audit has 7 Tailwind-related development/build advisories: 2 moderate, 5 high, 0 critical. Tailwind 4 migration was not forced. Python CVE coverage remains unassessed because pip-audit and safety were unavailable; Python dependencies are ranges with no lockfile.

## Known limitations

Advisory coverage may be unavailable. Static reachability does not prove exploitability or production exposure. Runtime observations are not production telemetry. SQLite is mutable/single-instance. No browser regression suite exists. Windows file-symlink regression was unavailable on the audit host. The ignored local .env is not part of this manifest or repository content and must remain untracked.

## Demo

Synthetic offline fixture: python .\osprey\examples\phase10-offline-demo\run_demo.py. It uses no real package advisory, exploit, or credential; approval modifies only temporary fixture files. The Copilot is demonstrated separately through the authenticated backend and is not faked by the offline fixture.

## Verification evidence

- Backend/API: 148 passed, 1 skipped.
- Shared scanner/CLI: 141 passed.
- Dedicated security suite: 33 passed, 1 skipped.
- pip check: no broken requirements.
- Frontend TypeScript and production build: passed; updated Vite 6.4.4 lockfile was clean-installed with lifecycle scripts disabled.
- Offline demo: proposal applied to temporary copy; scoped verification returned VERIFIED.
- Final offline scan: 175 source files, 240 components, 1,096 call edges (389 inter-file), 0 findings, advisory coverage unavailable for 240/240 components. Zero findings with unavailable advisory coverage does not mean zero vulnerabilities.
