# Runtime Reality

**Status:** REAL, bounded Python instrumentation and local installation metadata inspection. Process attachment, production telemetry, JavaScript/Python automatic instrumentation, and general runtime discovery are ROADMAP.

## State semantics

Runtime and package states are independent observations, not a single Boolean:

| State | Meaning |
|---|---|
| `DECLARED` | A supported project manifest names the dependency. |
| `LOCKED` | A supported lockfile records its resolved version. This does not mean installed. |
| `INSTALLED` | Bounded local package metadata for the matching version was found. |
| `LOADED` | Explicit Python instrumentation observed an already-imported module whose origin is listed by installed distribution metadata. |
| `EXERCISED` | A caller explicitly wrapped a module-owned callable and it returned successfully. Arguments and return values are not captured. |
| `UNKNOWN` | Osprey has no valid evidence for that state. Missing evidence is never a negative observation. |

`OBSERVED` in API/CLI state maps means evidence supports the state. It does not imply that every earlier state was separately proven. Ordinary scans do not attach to or launch applications. Their loaded/exercised states remain `UNKNOWN` and the report says runtime observation is unavailable.

## Evidence and provenance

Python runtime instrumentation is opt-in and process-local. The caller must already have imported the module, then explicitly call the instrumentation helper. Osprey validates the module-to-distribution mapping and installed file metadata. `EXERCISED` records reference the matching `LOADED` evidence. Runtime records retain package/version, module/symbol when known, process ID, Python version, a caller-provided non-sensitive environment label, collector/analyzer version, observation time, and limitations. The collector does not capture arguments, results, environment variables, or full local paths.

Evidence uses the existing canonical content identity and envelope hash. Identity excludes observation timestamp so equivalent normalized observations can compare; the envelope hash covers the stored timestamp and metadata. Hash mismatch detects altered covered data. SQLite and local process memory are mutable: this is integrity checking, not immutable or tamper-proof storage, trusted timestamping, source authenticity, or forensic chain-of-custody.

Runtime observations expire for current-state interpretation after 24 hours by default. Future timestamps beyond five minutes, invalid timestamps, stale evidence, malformed records, and tampered records do not establish current `LOADED` or `EXERCISED` state. The evidence may remain available for historical comparison with its limitation.

## Static and runtime together

Static reachability remains independent. A statically `REACHABLE` finding remains reachable if runtime evidence is absent or says the module was not observed in one instrumented process. Runtime evidence is scoped to the observed process, version, and labeled environment; it does not establish production deployment or safety elsewhere. This integration only supplies the existing shared risk engine's runtime-presence input when a current validated `LOADED` observation exists. No runtime observation contributes no factor; it is not a zero or a safety conclusion. Runtime evidence does not prove exploitability.

## Installation inspection and boundaries

The workspace scanner reads bounded `node_modules` package metadata and project-local Python virtual-environment distribution metadata when safely present. It does not install dependencies, import scanned project code, execute startup commands, attach to processes, inspect arbitrary process memory, or claim a lockfile proves installation. Paths are repository-relative. This local lookup is environment-specific and is not a complete package-manager resolver.

The Python instrumentation helper is an explicit opt-in library API. No automatic application hook or CLI option currently invokes it. No runtime events are fabricated during workspace scans. Runtime observation does not prove exploitability, absence of vulnerabilities, production exposure, internet reachability, compromise, or forensic chain of custody. Unsupported runtimes and absent telemetry remain `UNKNOWN`.
