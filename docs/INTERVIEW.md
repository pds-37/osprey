# Osprey interview notes

These answers describe the current code and its limits. They are prompts for accurate discussion, not claims of complete security coverage.

## Product

**Why did you build Osprey?** I wanted to examine the gap between a dependency advisory match and evidence that supported application code reaches the affected operation, without pretending static analysis proves exploitability.

**What problem does it solve?** It organizes package/version, symbol, reachability, runtime, risk, and remediation evidence into a reviewable workflow. It supplements dependency scanning; it does not replace a full application security program.

**How is it different from Dependabot/Snyk-style scanning?** Those products include broader ecosystem and workflow capabilities. Osprey's project focus is to connect available advisory-mapped vulnerable symbols to a bounded static route-to-call path and preserve the evidence/unknown state. I do not claim better coverage or accuracy than those tools.

## Architecture

**Why split shared engine and backend?** The CLI and API reuse parsers, evidence contracts, version evaluation, source/reachability analysis, risk, and remediation logic. FastAPI handles identity, request validation, persistence, and presentation adapters.

**Why SQLite?** It keeps local development and single-instance operation simple and makes persistence tests easy. It is not used as a distributed or enterprise multi-tenant database; the local file owner can modify it.

**Why not Postgres, Redis, or Kubernetes?** The current workload and deployment model do not justify those operational dependencies. Adding them without a concrete consistency, scale, or availability requirement would not improve the implemented security boundary.

## Security and trust boundaries

**How did you discover the Phase 9 workspace-isolation bug?** I tested direct workspace-path selection across authenticated organizations. Canonical containment kept requests inside the configured root, but that alone did not prove the requesting organization owned a sibling workspace. The audit reproduced cross-organization analysis/proposal access. The fix fails closed for local workspace scan/remediation when multiple organizations share a root without an explicit per-organization workspace mapping; regression tests cover the behavior. Details are in `SECURITY_AUDIT_PHASE9.md`.

**What was the hardest bug?** Preserving useful reachability evidence across files without silently treating unsupported syntax as a negative or positive result. A separate concurrency review found a remediation replay race; an atomic SQLite claim and regression test now prevent two simultaneous requests from claiming the same approved transition. The two filesystem replacements are still not an OS-level multi-file transaction.

**How does Osprey prevent IDOR?** Protected API routes use bearer authentication and roles. Object-bearing services compare persisted object organization/ownership before returning it. Workspace scanning additionally enforces a configured root and fails closed when multiple organizations share one unpartitioned local root. Not every legacy/global service is equivalent to a full tenant-isolated deployment, which is why deployment is single-instance/local.

**How does it handle prompt injection?** Repository/advisory text is treated as untrusted evidence. The model can select among server-created keys only; Osprey validates provider output and renders claims from evidence records. The model cannot create findings, scores, evidence IDs, or workflow transitions. Provider failure falls back to deterministic output.

**Why isn't AI the source of truth?** Model output is probabilistic and can be manipulated by malicious content. Version status, evidence integrity, reachability status, and risk are computed deterministically and presented with limitations.

## Analysis and risk

**How does vulnerable-symbol detection work?** Osprey consumes symbol mappings present in supported advisory metadata and compares them with calls extracted from supported source syntax. Missing mappings or unsupported syntax do not become a positive reachability claim.

**How are aliases handled?** The analyzer resolves only the alias/import forms implemented in its bounded parser and graph. Re-exports, namespace/destructured forms, dynamic/computed imports, and indirect calls can be incomplete; those cases must remain unknown where resolution is not established.

**How are dynamic imports handled?** Dynamic or computed imports are not treated as resolved module edges unless a supported literal form is explicitly recognized. Unresolved module behavior remains a limitation/`UNKNOWN`, not an assumed reachable or safe result.

**Why static reachability?** It can add application-specific context using source without executing the target application. Its supported syntax and call graph are incomplete, so it is an evidence layer rather than proof.

**Why not just use CVSS?** CVSS describes vulnerability characteristics. Osprey preserves it when available and adds separate application/context evidence such as version, route-to-symbol reachability, runtime observations, EPSS, and KEV. Its combined score is a project-specific prioritization metric, not a replacement standard.

**How does Osprey avoid claiming exploitability?** `REACHABLE` means a supported static path was observed. A route declaration does not prove public ingress, authentication bypass, runtime invocation, deployed package state, or a successful exploit. Those remain separate or unknown.

**How do false positives and false negatives arise?** Advisory ranges/symbol mappings can be incomplete or inaccurate; syntax/call resolution can over- or under-approximate behavior; framework conventions, generated code, reflection, dynamic imports, and runtime configuration are only partly modeled. Evidence confidence and limitations are retained; `UNKNOWN` is preferred over guessing.

**What does UNKNOWN mean?** The available sources and supported analysis cannot establish a value. It is not equivalent to safe, absent, or not vulnerable.

**What does Tree-sitter do?** Tree-sitter parses selected JavaScript, TypeScript/TSX, and Go files into syntax trees. Osprey applies AST-node caps and reports parser recovery/limits. Python uses `ast`. The analysis does not run code and is not a semantic compiler.

## Evidence and operations

**How did you discover the Phase 9 workspace-isolation bug?** Direct-ID/path substitution testing showed that being beneath the configured root did not establish organization ownership. Multi-organization local workspace operations now fail closed without per-organization roots. Regression coverage is in `tests/security/test_organization_isolation.py`.

**How is evidence integrity handled?** Canonical content and record-envelope hashes detect changed payloads/envelopes when records are verified. SQLite remains mutable; this is tamper-evident storage without trusted timestamps or independent custody.

**What runtime evidence exists?** Bounded installation metadata and opt-in process-local Python instrumentation for already imported modules/caller-wrapped callables. There is no process attachment, container, cloud, or production telemetry collector.

**How does remediation prevent replay?** The API workflow records approval and uses a serialized conditional SQLite state transition for the apply claim. The shared file applier rechecks proposal identity and input hashes immediately before replacing only the supported npm metadata files. A crash between multiple replacements cannot be made fully atomic with ordinary independent filesystem renames.

**What does VERIFIED mean?** The post-scan observed the expected target in the lockfile, had complete advisory coverage under the retained supported range, and found no equivalent affected copy in analyzed scope. It is not installation, runtime, deployment, or exploitability verification.

**How does performance scale?** Workspace traversal, manifest/source bytes, file counts, components, AST nodes, call-graph depth, API body/context size, and Copilot evidence are bounded. These are limits for a developer tool, not a benchmarked large-monorepo service.

**What was threat modeled?** Malicious repositories, dependency/advisory content, authenticated/unauthorized users, model-provider output/failure, path escape, parser crashes, stale evidence, remediation replay, and resource exhaustion. See Phase 9's threat model and regression results.

**What would you change for production?** First define and test an explicit per-organization workspace mapping and deployment isolation model; then add browser regression coverage, supported runtime telemetry, locked/audited Python dependencies, and operational controls appropriate to a hosted service. I would not claim the current local SQLite design is production multi-tenant.

**What are the biggest remaining limits?** Incomplete static semantics and advisory coverage; local single-instance SQLite and no full organization-to-workspace partition mapping; no Python lockfile, browser tests, or production runtime/cloud evidence; some API services remain single-organization compatibility surfaces.

## Questions to practice

- **How is workspace isolation tested?** API tests substitute IDs across organizations and check server-side 404/authorization outcomes; local workspace scans reject ambiguous multi-organization mapping. Filesystem tests exercise traversal and link/reparse handling.
- **Can a malformed provider response change a finding?** No. The provider selects a bounded subset of existing facts; malformed output falls back to evidence-only rendering.
- **Can remediation run arbitrary code?** The workflow does not invoke a package manager, shell, project command, lifecycle script, or model tool. It edits only supported npm JSON files after approval.
- **Does zero findings mean clean?** No. Interpret it alongside advisory coverage and scan limitations; unavailable coverage means unknown vulnerability coverage.
