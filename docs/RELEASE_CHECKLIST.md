# Release Checklist

A checked item means assessment/verification is complete; it does not mean no residual risk exists.

- [x] Repository baseline captured; pre-existing changes preserved and distinguished from Phase 11.
- [x] No secret-pattern matches in tracked/source text scanned.
- [x] Dependencies audited.
- [x] Frontend advisories assessed; Vite upgrade applied/tested; 7 residual advisories documented.
- [x] Python dependency constraints/reproducibility assessed; vulnerability audit attempted.
- [x] Frontend lockfile consistency verified by clean npm ci --ignore-scripts.
- [x] Clean Python install, pip check, backend/API tests, and shared Osprey tests verified.
- [x] Backend start and CLI entry point smoke-tested in the clean environment.
- [x] Backend and security suites pass.
- [x] CLI/shared scanner suite passes.
- [x] Copilot tests pass as part of the suites.
- [x] Frontend TypeScript validation and production build pass.
- [x] Offline demo reaches narrow deterministic VERIFIED state after explicit approval.
- [x] Final read-only workspace scan completed with isolated empty advisory cache.
- [x] Documentation reflects the assessed dependency/security posture.
- [x] License metadata assessed; no full legal review performed.
- [ ] Worktree clean and release changes intentionally staged. Phase 0-10 work was already present as a dirty worktree at Phase 11 start; no commit or tag was created.
- [ ] Python CVE audit completed with supported tooling. pip-audit and safety were unavailable.
- [ ] Remaining Tailwind advisories remediated or accepted after reviewed Tailwind 4 migration.
- [ ] Unified release version chosen/applied, if desired.
- [x] Repository-root MIT license added from the existing declared license text.
- [ ] Browser regression suite added; none is currently configured.

## Local credential handling

An ignored, untracked repository-root .env exists and contains a non-empty GEMINI_API_KEY. Its value was not displayed or validated. Do not include .env in source archives, screenshots, logs, or commits. Confirm locally whether it is real and rotate if applicable. The .env is excluded by .gitignore; this checklist does not claim an ignored local file is safe to publish.
