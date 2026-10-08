# OSPREY

**Evidence-Driven Software Supply Chain Security**

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB) ![MIT License](https://img.shields.io/badge/license-MIT-blue)

> Don't just find vulnerable dependencies. Find the vulnerabilities that actually matter.

Traditional dependency scanning often stops at package and version matching: `Package -> Version -> Advisory`. Osprey continues with advisory-mapped symbols, bounded application reachability, runtime observations, deterministic risk, remediation, verification, and evidence. Its pipeline adds context; it does not prove exploitability or production exposure.

## The problem

Traditional dependency scanners are useful for identifying packages whose versions overlap advisory ranges. That is necessary, but it does not show whether application code calls the vulnerable functionality, whether the package is loaded in a running process, or whether a deployed service is exposed. Osprey adds evidence layers for those questions while preserving the limits of each layer.

## Solution

Osprey correlates available dependency/advisory data with source-level symbol and reachability evidence, then carries supported observations through deterministic risk, scoped remediation, and verification. Copilot can explain that record but cannot change it.

## Key differentiator

The project keeps package matching, vulnerable-symbol mapping, static reachability, runtime observations, risk, and verification as separate evidence claims. It does not convert an import into exploitability or missing data into a clean result.

## Why Osprey

**Traditional scan:** Package -> Version -> Advisory

**Osprey:** Package -> Version -> Vulnerable Symbol -> Reachability -> Runtime Evidence -> Risk -> Remediation -> Verification -> Evidence


- Inventories supported npm, Python, Docker/Compose inputs and CycloneDX, SPDX, or Syft SBOMs.
- Evaluates observed versions against OSV advisory data, with an offline local cache option.
- Parses bounded Python, JavaScript, TypeScript/TSX, and Go syntax to collect selected imports, functions, calls, and route declarations.
- Attempts conservative route-to-vulnerable-symbol reachability and returns `REACHABLE`, `NOT_REACHABLE`, or `UNKNOWN` with limitations and evidence references.
- Records declared, locked, installed, loaded, and exercised observations separately. Ordinary scanning does not run or attach to the target application.
- Calculates deterministic risk from supported evidence; missing factors remain unknown and coverage is reported.
- Stores backend observations, evidence, findings, audit events, and remediation workflow state in local SQLite.
- Creates bounded npm remediation proposals. Admin approval is explicit; application changes only the supported manifest/lockfile pair, rechecks input state, and does not invoke npm or project code.
- Provides an evidence-grounded read-only Copilot. A configured model can rank server-created fact keys; Osprey renders the facts and owns the risk and state.

## Capability matrix

| Capability | Status |
|---|---|
| Dependency inventory and advisory/version matching | Implemented for documented inputs; coverage depends on available data |
| Vulnerable-symbol analysis | Implemented when advisory metadata maps symbols |
| Static and inter-file reachability | Bounded; unsupported behavior remains `UNKNOWN` |
| Runtime evidence | Bounded local observations; unavailable in ordinary offline workspace scans |
| Deterministic risk | Implemented; missing required evidence remains `UNKNOWN` |
| Evidence and provenance | Implemented; tamper-evident, not immutable |
| npm remediation | Supported files only; explicit approval required |
| Verification | Scoped deterministic rescan, not runtime/deployment verification |
| Copilot | Optional, evidence-grounded, read-only explanation |
| Multi-tenant production deployment | Not supported |

## What Osprey does not claim

Osprey does not prove exploitability or production exposure, guarantee vulnerability-free dependencies, provide complete static analysis, provide immutable evidence, or perform autonomous remediation. It also does not determine production deployment state, complete call-graph reachability, cloud/IAM exposure, continuous repository status, or production runtime telemetry. A `VERIFIED` remediation state is scoped to the deterministic local rescan conditions documented in [Remediation](docs/REMEDIATION.md).

## Architecture and workflow

~~~mermaid
flowchart TD
  subgraph Engine[Deterministic Osprey Engine - source of truth]
    A[Dependency Inventory] --> C[Version Matching]
    B[Vulnerability Intelligence] --> C
    C --> D[Vulnerable Symbol]
    D --> E[Bounded Static Reachability]
    E --> F[Runtime and Installation Evidence]
    F --> G[Deterministic Risk Engine]
    G --> H[Evidence and Provenance]
    H --> I[Approval-Gated Remediation]
    I --> J[Verification]
    J --> H
  end
  H --> K[Evidence-Grounded Copilot - READ ONLY]
~~~

The Copilot is downstream of deterministic evidence and cannot set risk or change state. See [Architecture](docs/ARCHITECTURE.md), [Evidence Model](docs/EVIDENCE_MODEL.md), [Reachability](docs/REACHABILITY.md), and [AI Security Boundary](docs/ai-security.md).

## Risk model

The shared deterministic engine combines available version, severity/CVSS, EPSS, KEV, exposure, reachability, runtime, and dependency evidence using documented weights and coverage. It reports a score/decision only when its required evidence signals exist; otherwise the result remains `UNKNOWN`. This project-specific triage is not CVSS, a probability of exploitation, or proof that a vulnerability is exploitable. AI output does not set risk values.

## Reachability

The analyzer attempts a limited static route-to-call path when an advisory provides a package-scoped vulnerable symbol and supported syntax connects the observed route to that symbol. `NOT_REACHABLE` is limited to the analyzed files and supported syntax. Dynamic dispatch, framework behavior, reflection, generated code, unsupported syntax, and incomplete files can leave the result unknown. A package-level finding by itself is not reachability evidence.

## Runtime evidence

Inventory distinguishes manifest declaration, lockfile resolution, and bounded local installation metadata. An opt-in Python helper can observe an already imported module and an explicitly wrapped callable. Scans do not start applications, attach to processes, or collect container, cloud, or production telemetry. Missing runtime observations remain `UNKNOWN`; details are in [Runtime Reality](docs/RUNTIME_REALITY.md).

## Evidence and provenance

Evidence records carry source, location, time, confidence, content hash, and structured observations. Backend SQLite integrity checks are **tamper-evident**, not immutable or tamper-proof. Hashes do not independently establish source authenticity, trusted time, or chain of custody. See [Evidence Model](docs/EVIDENCE_MODEL.md).

## Remediation

The implemented shared workflow is limited to supported npm `package.json` and package-lock v2/v3 inputs. Proposal creation is read-only; applying requires explicit admin approval and fresh content checks. No package manager, install script, or project command is executed. Verification can return `FAILED`, `UNKNOWN`, or `VERIFIED`; a verified lockfile classification does not establish installation, runtime behavior, deployment, or exploitability. See [Remediation](docs/REMEDIATION.md).

## AI Copilot

The default is deterministic evidence-only output. An optional OpenAI-compatible provider receives bounded context and may choose only among server-created fact keys. It cannot provide authoritative IDs, scores, statuses, or state changes. The provider is not enabled by default. See [AI Security](docs/ai-security.md).

## Security Philosophy

- The deterministic engine is authoritative; Copilot cannot override findings, risk, or workflow state.
- Evidence is **tamper-evident**, not immutable.
- Missing or unsupported evidence stays `UNKNOWN`.
- Remediation requires explicit approval and is limited to supported files.
- Parsing and analysis are bounded; repository content is untrusted input.
- Copilot is a read-only explanation layer with bounded evidence context.

## Security model

The API uses configured bearer JWT accounts and `viewer`, `security_engineer`, and `admin` roles. Objects are scoped to the authenticated organization where implemented; local filesystem scan/remediation fails closed in ambiguous multi-organization configurations because there is no per-organization workspace mapping. SQLite is intended for a local, single-instance deployment, not distributed multi-tenant operation. Review [Security Model](docs/SECURITY_MODEL.md), [Threat Model](docs/threat-model.md), and [Phase 9 Audit](docs/SECURITY_AUDIT_PHASE9.md).

## Known limitations

Static reachability and runtime evidence are bounded; advisory coverage may be incomplete or unavailable. SQLite is local and mutable. Python dependencies use version ranges without a lockfile, and Python CVE coverage is unassessed. Seven disclosed development/build-time npm advisories remain (2 moderate, 5 high). There is no browser regression suite or production telemetry, and Osprey is not a production multi-tenant service. This is not a security certification. See [Release](docs/RELEASE.md), [Phase 9 Audit](docs/SECURITY_AUDIT_PHASE9.md), [Architecture](docs/ARCHITECTURE.md), and [Testing](docs/TESTING.md) for detail.

The Python project has ranged dependencies and no lockfile. A clean Python 3.14 install and test run passed, but installs are not guaranteed to resolve identical versions later. Use [Testing](docs/TESTING.md) for verified commands. The root .env.example contains placeholders only; the current backend reads COPILOT_API_KEY for its optional OpenAI-compatible provider. It does not read GEMINI_API_KEY.

## Quick start (Windows PowerShell)

Requirements: Python 3.10+, Node.js/npm for the frontend. Run commands from the repository root unless stated otherwise.

Clone the public repository with:

    git clone https://github.com/pds-37/osprey.git
    Set-Location osprey


```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .\osprey
python -m pip install -r .\backend\requirements.txt
python -m osprey.cli scan . --offline
```

Offline scans use only the local OSV cache. An empty or stale cache means advisory coverage can be unavailable; it does not mean the repository has no vulnerabilities. To allow OSV lookups, omit `--offline`.

### Start the backend

In a new PowerShell window, from the repository root:

```powershell
python -m pip install -r .\backend\requirements.txt
$env:PYTHONPATH = "backend;osprey\src"
$env:STATE_DB_PATH = ".\osprey-state.sqlite3"
$env:SECRET_KEY = "replace-with-a-random-secret-at-least-32-bytes"
python -m uvicorn guardianos.api.app:app --app-dir backend --host 127.0.0.1 --port 8000
```

This is a local development configuration. Configure `AUTH_USERS_JSON` with password hashes before login. Generate one with:

```powershell
$env:PYTHONPATH = "backend;osprey\src"
python -c "from guardianos.core.security import get_password_hash; print(get_password_hash('replace-with-a-local-password'))"
```

Use the returned hash in a local environment variable, for example:

```powershell
$env:AUTH_USERS_JSON = '{"local-admin":{"password_hash":"<generated-hash>","role":"admin","org_id":"local"}}'
```

Do not commit real hashes, passwords, API keys, or signing keys. Production startup requires an explicitly configured signing key. See [.env.example](.env.example) for placeholder names and [Deployment](docs/deployment.md) for configuration caveats. Configure SECRET_KEY and AUTH_USERS_JSON for authenticated use; WORKSPACE_ROOT and STATE_DB_PATH select local workspace/state paths. COPILOT_API_KEY is optional and only used if a remote Copilot provider is explicitly configured.

### Start the frontend

```powershell
Set-Location frontend
npm ci --ignore-scripts
npm run dev
```

The lockfile install was validated with lifecycle scripts disabled; the frontend production build succeeds in that configuration. Open the local Vite URL shown in the terminal. API docs are at `http://127.0.0.1:8000/api/docs` when the backend is running. The current frontend dependency audit reports unresolved development-tool advisories; see [Testing](docs/TESTING.md).

## Example output

The CLI reports inventory and findings with advisory coverage, risk decision, reachability, runtime observations, evidence identifiers, and limitations. Output fields vary with input and cache state; do not interpret `0 findings` as `0 vulnerabilities` when advisory coverage is unavailable.

## Example finding

The offline demonstration uses fictional data: **demo-codec@1.0.0** matches synthetic advisory **DEMO-OSPREY-0001**, whose metadata maps **decodeUnsafe**. The supported route-to-symbol path is **REACHABLE**; installation, loaded/exercised runtime state, and risk remain **UNKNOWN** when required evidence is absent. The fixture can generate a constrained proposal to update only its temporary manifest/lockfile and verify the rescan. This is illustrative analyzer evidence, not a real vulnerability or exploit.

## Reproducible demo

Run the offline synthetic fixture and demonstration described in [Demo](docs/DEMO.md). It seeds a temporary isolated advisory cache and uses fictional package metadata; it does not use a real exploit, secret, or live feed. The fixture is not evidence about a real package.

## Testing

On a configured Windows checkout, the full documented verification entry point is:

```powershell
.\verify.ps1
```

The script runs backend/API tests, shared scanner/CLI tests, `pip check`, and the frontend TypeScript/production build. See [Testing](docs/TESTING.md) for component-level commands and known coverage gaps. The frontend currently has build validation but no browser/component test suite.

## Project structure

```text
backend/guardianos/       FastAPI adapter, authorization, SQLite, services
osprey/src/osprey/        Shared scanner, parsers, evidence, risk, CLI
osprey/examples/          Offline synthetic walkthrough fixture
frontend/                 React/Vite API client and dashboard
tests/                    Backend/API/security tests
osprey/tests/             Shared engine and CLI tests
docs/                     Architecture, API, security, demo, and limitations
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [API](docs/api.md)
- [Security model](docs/SECURITY_MODEL.md), [threat model](docs/threat-model.md), and [Phase 9 audit](docs/SECURITY_AUDIT_PHASE9.md)
- [Release posture](docs/RELEASE.md) and [release checklist](docs/RELEASE_CHECKLIST.md)
- [Demo guide](docs/DEMO.md) and [interview script](docs/DEMO_SCRIPT.md)
- [Portfolio summary](docs/PORTFOLIO_SUMMARY.md) and [elevator pitch](docs/ELEVATOR_PITCH.md)

## License

Osprey is distributed under the MIT License. See [LICENSE](LICENSE).
