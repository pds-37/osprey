# Osprey Portfolio Summary

### What I built

Osprey is a Python/TypeScript software supply-chain security project. It inventories dependencies, matches observed versions to available advisory data, and attempts bounded route-to-vulnerable-symbol reachability. It records provenance-bearing evidence, computes deterministic risk, supports explicit npm remediation approval, and offers an evidence-grounded read-only Copilot.

### Why I built it

Package-level alerts identify useful risk, but do not show whether supported application code reaches an advisory-mapped operation. Osprey explores that question while preserving UNKNOWN when evidence or syntax support is incomplete.

### Hardest technical problem

Connecting advisory symbol metadata to supported source paths across files without turning syntax guesses into exploitability claims. The parser and graph are intentionally bounded and expose limitations.

### Security vulnerability discovered during audit

Phase 9 exposed a workspace-isolation flaw: canonical containment under one configured root did not prove that a user organization owned a sibling workspace. The fix disables local scan/remediation in multi-organization mode until explicit per-organization roots exist; tests cover the fail-closed behavior. A separate concurrency review also added a serialized SQLite claim to prevent duplicate remediation apply transitions.

### Strongest differentiator

The evidence chain connects package/version observations, advisory symbols, supported route-to-call paths, risk inputs, and scoped remediation/verification. Unknown evidence remains explicit, and Copilot cannot override the deterministic record.

### Architecture

- React/Vite frontend calls a FastAPI backend.
- The Python Osprey package supplies scanner, parsers, risk, evidence, reachability, remediation, and CLI functionality.
- Backend state is local SQLite; static graph analysis uses NetworkX.
- Optional external advisory/model requests are separate trust boundaries.
- Copilot is downstream and read-only.

### Security model

Configured bearer-token users have role and organization checks on protected APIs. Object access is checked server-side. Workspace operations fail closed in ambiguous multi-organization setups. Evidence records are tamper-evident, not immutable. Remediation requires explicit approval and does not execute npm or project commands.

### Key engineering decisions

- Deterministic scanner/risk code is authoritative; model output cannot set scores or state.
- Static reachability is evidence, not exploit proof.
- SQLite keeps local setup simple but is not presented as distributed or immutable.
- Dependency updates are compatibility-tested instead of forced across major versions.

### Limitations

Python dependency ranges are not locked; Python CVE audit tooling was unavailable. Seven Tailwind-related frontend development/build advisories remain (2 moderate, 5 high). There is no browser regression suite or production runtime telemetry. Parser and reachability coverage is bounded.

### Tech stack

Python 3.10+, FastAPI, Pydantic, Tree-sitter, NetworkX, SQLite, Typer, React, TypeScript, Vite, and npm.

### Results

On the audited worktree, backend/API tests passed 148 with 1 host-dependent skip; shared Osprey tests passed 141; the dedicated security selection passed 33 with 1 skip; pip check and frontend TypeScript/production build passed. The final offline repository scan reported 175 source files and 240 components, but advisory coverage was unavailable for all 240, so zero findings is not a zero-vulnerability claim.
