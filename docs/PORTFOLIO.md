# OSPREY — Evidence-Driven Software Supply Chain Security

## Problem

Traditional dependency scanners often stop at “Package X contains CVE Y.” Osprey asks the next question: “Does this application statically reach the advisory-mapped functionality, and what evidence supports that assessment?”

## Technical approach

- **Symbol-level analysis:** advisory-provided vulnerable-symbol metadata is scoped to the affected package; supported imports and calls are parsed as source observations.
- **Inter-file reachability:** a bounded call graph attempts to connect observed HTTP handlers to those symbols. Unsupported or dynamic behavior remains `UNKNOWN`.
- **Runtime evidence:** declared, locked, installed, loaded, and exercised states remain separate. Runtime collection is intentionally narrow and opt-in.
- **Deterministic risk:** a shared evidence-aware engine consumes available factors and exposes coverage and limitations. AI does not set authoritative risk.
- **Evidence provenance:** structured observations carry identifiers and hashes. Hash checks are tamper-evident; the SQLite database is still mutable.
- **Remediation:** bounded npm proposals require explicit approval and fresh input checks. The implementation edits only supported package metadata and does not run npm.
- **Verification:** a local rescan can verify a narrow lockfile/advisory condition or report failed/unknown. It does not establish installation or deployment.
- **Copilot:** read-only, finding-scoped summaries are rendered from verified Osprey records. A remote provider is optional and untrusted.

## Architecture

The shared Python package contains the CLI, parsers, evidence contracts, source analyzer, reachability, risk calculation, and remediation helpers. FastAPI provides auth/role checks, organization-aware persistence, API adapters, and Copilot context. SQLite stores local document records; NetworkX graph state is derived in process. A React/Vite frontend consumes the API. The evidence flow and capability limits are in [Architecture](ARCHITECTURE.md).

## Honest scope

Osprey is a portfolio implementation of evidence-oriented dependency triage, bounded static reachability, defensive uncertainty handling, and approval-gated local remediation. It is not an exploitability proof, complete call graph, cloud exposure scanner, production runtime monitor, immutable evidence system, or production multi-tenant service. The offline demo uses synthetic advisory data and is labeled as such.
