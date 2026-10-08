# Testing and verification

## One-command project verification

From the repository root in Windows PowerShell, after installing the declared development dependencies:

```powershell
.\verify.ps1
```

The fail-fast script runs backend/API tests (`tests/`), shared engine and CLI tests (`osprey/tests/`), `pip check`, then the frontend TypeScript check and Vite production build. It does not install dependencies or modify project manifests. Python suites run sequentially because the root pytest configuration and standalone Osprey project have separate test roots.

## Component commands

```powershell
.\.venv\Scripts\python.exe -m pytest -q
Push-Location .\osprey
..\.venv\Scripts\python.exe -m pytest -q
Pop-Location
.\.venv\Scripts\python.exe -m pip check
Push-Location .\frontend
npm ci
npm run build
Pop-Location
```

To run focused areas, use the existing named tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\security -q
.\.venv\Scripts\python.exe -m pytest tests\integration\test_remediation_workflow_api.py tests\unit\test_copilot.py tests\unit\test_runtime.py -q
Push-Location .\osprey
..\.venv\Scripts\python.exe -m pytest tests\test_source_reachability.py tests\test_symbol_mappings.py tests\test_osv_mock.py tests\test_risk.py tests\test_remediation.py -q
Pop-Location
```

The offline deterministic walkthrough can be run with `python .\osprey\examples\phase10-offline-demo\run_demo.py`; it uses temporary files and an isolated cache.

## Last verified Phase 9 baseline (2026-10-09)

- Backend/API suite: **148 passed, 1 skipped (149 collected)**.
- Shared Osprey scanner/CLI suite: **140 passed**.
- Focused security, remediation-workflow, and SQLite selection: **42 passed, 1 skipped (43 collected)**.
- Four dedicated parser regressions passed in the backend suite; malformed/deep/large JS, TS, TSX, Python, and Go probes ran in subprocesses without native crash.
- Risk-input adversarial selection: **15 passed**.
- Frontend `npm run build`: passed (TypeScript and Vite production build).
- `pip check`: no broken requirements.
- Offline scan: 171 source files, 233 components, 1,087 call edges (382 inter-file), 0 findings, 0 runtime observations, 686 limitations, 4 Tree-sitter recovery limitations, 1 AST-limit event, no crashes. Advisory coverage was `UNAVAILABLE` for all 233 components; zero findings do not establish no vulnerabilities.

Phase 10 final run: backend/API suite **148 passed, 1 skipped (149 collected)**; shared Osprey suite **141 passed** (including the new cache-handle regression); `pip check` clean; frontend TypeScript and Vite production build passed with 1,493 modules transformed. The synthetic offline demo was run with approval against its temporary copy and returned `VERIFIED` under synthetic complete advisory coverage. Generated OpenAPI comparison found **53 of 53 routes documented**. The README backend command was smoke-tested on loopback, with `/health` and `/ready` returning 200. Final scan metrics are recorded in `PROJECT_STATUS.md`.

The initial frontend audit reported 9 development-tool advisories (3 moderate, 6 high), including Vite/esbuild and Tailwind's dependency tree. Phase 11 upgraded Vite to 6.4.4 and reran the lockfile audit: **7 remain (2 moderate, 5 high, 0 critical)**, all in the Tailwind development/build-time tree. Tailwind 4 is a major migration and was not forced. These findings still affect local development/build environments; see `RELEASE.md` for package/version details.

## Test boundaries

- `tests/` covers backend/API, authentication/roles, organization scope, evidence, SQLite persistence, shared risk/reachability/runtime/remediation, Copilot, and security regressions.
- `osprey/tests/` covers CLI, shared scanner, static parser/reachability, versioning, risk, evidence-backed explanation, and remediation.
- Frontend has no unit/component/browser suite. A successful build checks TypeScript and bundling, not browser behavior or accessibility.
- Parser adversarial tests detect the exercised failure modes, not all native parser crashes or worst-case inputs.
- No current `pip-audit`/`safety` tool was installed at baseline; Python dependency CVE status was not independently audited. `pip check` validates dependency consistency, not vulnerability status.
