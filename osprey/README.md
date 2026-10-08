# Osprey CLI

Osprey is a read-only CLI for software dependency inventory and vulnerability prioritization. It correlates manifests and lockfiles with OSV advisories, gathers EPSS and CISA KEV signals when online, and uses static source evidence to refine priority. It does not execute the scanned application.

## Install

Requires Python 3.10 or newer.

```powershell
python -m pip install -e .\osprey
```

## Scan

```powershell
osprey scan .
osprey scan . --detail
osprey scan . --json
osprey scan . --sarif report.sarif
osprey scan . --sbom sbom.json
osprey scan . --offline
osprey scan . --fail-on act-now
```

The scanner reads npm manifests/lockfiles, supported Python dependency files, Dockerfile/Compose declarations, and bounded Python, JavaScript, TypeScript/TSX, and Go source. It never installs dependencies, imports application modules, or executes project code.

## Evidence and reachability

The CLI records file and line provenance, content hashes, advisory source, and static source observations. A source route declaration proves only that route syntax exists in the scanned files; it does not establish public network access, authentication, deployment, or a running process.

When advisory metadata identifies a vulnerable symbol, Osprey attempts a local route-to-function-to-symbol path. It reports:

- `REACHABLE` when a supported path is present;
- `NOT_REACHABLE` only within the supported source subset when the imported dependency is observed but the mapped symbol is not reached by an observed handler;
- `UNKNOWN` when source, symbols, or syntax are insufficient.

Cross-file calls, dynamic imports, reflection, complete data flow, and many framework-specific constructs are not resolved. A package vulnerability remains distinct from function reachability.

## Priority tiers

The CLI and backend use one shared deterministic, evidence-aware risk engine. It reports a normalized score and risk level over observed factors, plus an `ACT NOW`, `PLAN`, `MONITOR`, `IGNORE`, or `UNKNOWN` decision. The score is not CVSS, an exploit probability, or an industry scoring standard.

An `ACT NOW` result requires a confirmed affected version, a high-confidence supported source path, and critical severity or explicit KEV/high EPSS evidence. `PLAN` retains higher-severity findings when reachability or exposure is unresolved; a bounded `NOT_REACHABLE` result does not erase package risk. `IGNORE` requires explicit evidence that the package is absent or the installed version is outside the affected range. Missing version or severity evidence remains `UNKNOWN`.

EPSS and KEV affect the result only when their values/catalog availability are known. Missing EPSS is not zero and unavailable KEV is not false. Exposure metadata can contribute as declared or user-asserted context, but a source route does not prove deployment ingress or Internet exposure. Risk results explain their factors and limitations; they do not prove exploitability or deployment exposure.

## Network and privacy

Online scans may contact OSV, FIRST EPSS, and CISA KEV endpoints. `--offline` disables network calls and uses the local cache. Osprey does not send telemetry. Review repository contents and the scan scope before scanning untrusted source.

Run CLI tests from the repository root with `python -m pytest -q .\osprey\tests`.

## Remediation

`osprey remediate FINDING_ID --path .` prints a read-only proposal. Controlled apply is narrowly limited to supported npm metadata and requires `--apply PROPOSAL_ID --approve`; it never runs npm, installs dependencies, or executes project code. See the repository's `docs/REMEDIATION.md` for supported inputs and limits. Unknown targets and post-scan uncertainty remain unknown.
