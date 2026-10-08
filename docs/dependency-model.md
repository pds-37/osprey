# Dependency Observation Model

Osprey records observations, not a single authoritative record per package. Two occurrences of the same PURL can have different source files, scan times, applications, or states and are retained separately.

## Canonical observation fields

A component observation carries ecosystem, package name, version, PURL, source, location, dependency type, observation ID, evidence IDs, and optional state-specific versions:

- `declared_version`
- `installed_version`
- `running_version`

Each field is populated only from an input that supports that state. The current model can hold several versions simultaneously, but automatic drift comparison is not yet implemented.

## State semantics

| State | What may establish it | Current support |
|---|---|---|
| `DECLARED` | Manifest or declaration file such as `package.json`, `requirements.txt`, or `pyproject.toml` | Shared workspace scanner records supported declarations. |
| `INSTALLED` | Lockfile resolution or a filesystem/container SBOM with suitable provenance | Lockfiles are represented as installed observations by the current workspace adapter; Syft/SBOM inputs retain their stated scope. |
| `RUNNING` | Legacy component label; it is not sufficient runtime evidence by itself | No SBOM can assert it. Phase 6 uses separate `LOADED`/`EXERCISED` evidence from explicit Python instrumentation; absent evidence stays `UNKNOWN`. |
| `UNKNOWN` | Input does not establish declared, installed, or running state | Default for generic or insufficiently sourced observations. |

`environment=production`, a Docker `EXPOSE` declaration, or a static `app.listen()` call does not establish that a package is running or internet-facing.

## Inventory sources currently supported

- Node.js: `package.json` and supported npm/yarn/pnpm lockfiles.
- Python: `requirements.txt`, `pyproject.toml`, and supported lockfiles.
- Container declarations: Dockerfile and Compose text; these do not inspect an image or daemon.
- SBOM: CycloneDX, SPDX, and Syft formats in the backend.

A workspace manifest observation and lockfile observation stay distinct even when the package name and PURL match. Backend persistence keys components by observation ID rather than PURL.

## Drift

The target model compares declared, installed, and running observations only when they share an application/component identity and compatible source scope. Drift detection and runtime collection are not yet implemented; Osprey must report `UNKNOWN` rather than claim that versions are aligned or drifting without comparable evidence.
