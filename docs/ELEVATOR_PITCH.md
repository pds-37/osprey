# Osprey Elevator Pitches

## 15-second pitch

Osprey is an evidence-driven software supply-chain security tool. It connects package advisory matches to bounded static evidence about vulnerable symbols and application call paths, while keeping risk deterministic and unknowns explicit.

## 30-second pitch

Traditional dependency scanning often stops when a package version matches an advisory. Osprey also checks whether supported source paths reach an advisory-mapped symbol, records runtime/install evidence separately, and calculates risk from deterministic evidence. It can propose a constrained dependency update, but a human must approve it. It does not prove exploitability or production exposure.

## 60-second pitch

I built Osprey to examine the gap between “this package version is affected” and “this application appears to reach the affected functionality.” It inventories dependency manifests and SBOMs, uses available advisory/version data, maps vulnerable symbols where metadata supports that, and runs a bounded static analyzer over supported source syntax. Results include provenance and limitations, while missing runtime, advisory, or application-context evidence stays UNKNOWN. A deterministic risk engine remains authoritative. Remediation proposals are limited to supported npm files, require explicit approval, and are rescanned for scoped verification. The Copilot is a read-only explanation layer over validated records. The system is a local portfolio release candidate; Python dependencies are not locked, seven frontend development advisories remain, and reachability is not proof of exploitability.

## Technical interview pitch

The implementation has a shared Python scanner and evidence model, a FastAPI/SQLite adapter, a Typer CLI, and a React/TypeScript frontend. Python AST and Tree-sitter parsers collect a bounded subset of imports, calls, and routes; reachability is conservative and returns UNKNOWN when resolution is incomplete. Deterministic risk consumes validated evidence. SQLite stores local state and uses transactional state claims for remediation replay resistance, but it is mutable and single-instance. The optional provider can only select server-authored Copilot fact keys; it cannot write risk or remediation state.

## Security interview pitch

I treated repository files, advisory data, user IDs, provider output, and workspace paths as untrusted. Phase 9 added adversarial regressions for organization/object isolation, malformed parser inputs, filesystem escapes, risk coercion, evidence integrity, Copilot context, and concurrent remediation. One replay race was fixed with an atomic SQLite state transition. The remaining limits are explicit: no parser wall-clock cancellation, host-dependent file-symlink coverage, local mutable SQLite, no production telemetry, and no complete static semantics. Phase 11 cleared the Vite advisories through a tested update but retained and disclosed the Tailwind development-tree advisories rather than forcing a major migration.
