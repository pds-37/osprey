# Osprey Evidence Model

**Updated:** 2026-10-08

## Record shape

The shared evidence contract records an ID, evidence type, source, location, timestamp, confidence, content hash, and metadata. Backend evidence is stored in SQLite and important API findings refer to evidence IDs. Raw source text is not retained by default.

Evidence categories emitted include dependency input (`MANIFEST`, `LOCKFILE`, `SBOM`), installation metadata (`INSTALLATION_OBSERVATION`), source observations (`SOURCE_FILE`, `IMPORT`, `ROUTE`, `FUNCTION`), vulnerability intelligence (`VULNERABILITY_ADVISORY`, `VERSION`, `VULNERABLE_SYMBOL`, `EPSS`, `CISA_KEV`), analysis (`SOURCE_EXPOSURE`, `REACHABILITY`, `ANALYSIS_LIMITATION`, `ANALYSIS_RUN`), risk (`RISK`), and explicit user assertions (`USER_INPUT`). `RUNTIME_OBSERVATION` is emitted only by explicit Python instrumentation; it does not represent automatic process or production telemetry. `CONTAINER_IMAGE` does not imply container runtime observation.

Reachability, risk, and limitation records retain a bounded normalized `metadata.observed` value. Reachability contains its status, confidence, path, edge records, reason, basis IDs, and limitations. Risk contains the exact normalized inputs and the shared engine's result, factors, explanation, and limitations. The metadata is included in the canonical evidence identity and envelope hash, is returned by the evidence API, and is persisted with the record. Raw source file contents remain omitted; their SHA-256 digest and relative source locations are retained. Advisory records preserve source, identifier, package/ecosystem, affected/fixed version evidence, and any severity/CVSS/EPSS/KEV values actually supplied. Missing values remain unavailable.

## Provenance rules

- Workspace parsers and static analyzers create evidence from files they actually read and locations they actually parse.
- Advisory matching creates advisory evidence from the actual OSV response or an explicitly identified bundled record.
- Endpoint profile assertions are `USER_INPUT`; they are not cloud ingress observations.
- A static route is source evidence only. It does not prove that the service is deployed, public, or reachable from the Internet.
- Demo values are synthetic. The demo response identifies itself as a fixture; fixture path, lifecycle, and related remediation records are flagged.
- Evidence IDs use canonical JSON with sorted keys and strict finite JSON values. Identical normalized evidence fields produce the same ID. The content hash is SHA-256 over the exact observed bytes (or canonical JSON where a structured observation is hashed). The separate record hash covers the stored envelope, including its observation timestamp. Altering a covered field produces an integrity mismatch.
- A SHA-256 hash supports content integrity checking only. SQLite is mutable; this design provides no immutable storage, trusted timestamp, independent custody, source authenticity, or forensic chain-of-custody guarantee. Legacy records without an envelope hash are reported `UNVERIFIED_LEGACY`.
- Relative source paths and line locations are observations from the analyzer. They are not separately persisted immutable callsite records; static call edges are not tamper-proof forensic artifacts.
- Runtime states are separate observations: declared, locked, installed, loaded, and exercised. Lockfiles do not prove installation; installation does not prove a module was loaded; a loaded module does not prove a vulnerable symbol ran. Missing runtime evidence is `UNKNOWN`. See [RUNTIME_REALITY.md](RUNTIME_REALITY.md) for the opt-in collector, freshness rules, and boundaries.

## Conclusion references

Vulnerability findings and reachability results include evidence IDs where available. A package-level affected result is distinct from function reachability. `REACHABLE` records an observed supported path; `NOT_REACHABLE` is bounded by the analyzed files and supported syntax; `UNKNOWN` carries its unresolved or unsupported reason when available. Missing or insufficient evidence remains `UNKNOWN` or `NOT OBSERVED`; absence of a record is not proof of safety.

The evidence summary endpoint only formats existing records. It does not create evidence, change finding status, approve remediation, or use a language model.
