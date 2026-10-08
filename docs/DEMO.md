# Osprey five-minute demo

The offline fixture at [`osprey/examples/phase10-offline-demo`](../osprey/examples/phase10-offline-demo) is synthetic. It seeds a fictional `DEMO-OSPREY-0001` into an isolated temporary OSV cache and copies its project into a temporary directory. Neither the original fixture nor the developer's advisory cache is modified. The scanned source is never executed. This demonstration is not evidence about any real package.

## Run the reproducible core

From the repository root in PowerShell, with the project's `.venv` configured:

```powershell
python .\osprey\examples\phase10-offline-demo\run_demo.py
```

The runner prints the actual shared scanner finding, source reachability, evidence IDs, advisory coverage, runtime unknowns, deterministic risk result, and a read-only remediation proposal. It also evaluates three isolated source cases: `REACHABLE`, `NOT_REACHABLE`, and `UNKNOWN`. When a proposal is available, type `APPROVE` to apply only the proposal to the temporary project copy; any other input declines. The script then rescans and prints the verification object before deleting the temporary files.

Expected properties, rather than hard-coded IDs or scores:

- The affected fictional dependency is `demo-codec@1.0.0`; the synthetic advisory maps `decodeUnsafe` and provides fixed version `1.1.0`.
- Manifest and lockfile entries remain separate component observations, so the scan can show more than one row for the same fictional advisory/package. This is observation identity, not several vulnerable packages.
- The route in `src/app.js` has a supported static path to the mapped symbol.
- The static-only result does not imply runtime use, public ingress, or exploitability. Runtime states remain unknown.
- Risk is calculated by the deterministic engine. In the current fixture the missing severity and application-context evidence yield `UNKNOWN`, not an invented numeric score.
- Advisory, source, version, and risk inputs are repeatable; evidence timestamps and temporary workspace identity can make record envelopes or IDs differ between runs. The demo does not promise byte-identical evidence envelopes.
- An approval changes only temporary `package.json` and `package-lock.json`; no package manager runs. The deterministic post-scan can report `VERIFIED` for the synthetic fixture because complete synthetic advisory coverage and the fixed range are present.

For an unapproved run, press Enter at the prompt. The fixture directory stays unchanged either way.

## Approximately five-minute presentation sequence

1. **00:00 - Problem:** Package/version matching does not show whether supported application code reaches the affected operation.
2. **00:30 - Scan:** Run the offline fixture and explain that its advisory data is synthetic.
3. **01:00 - Vulnerable dependency:** Show fictional `demo-codec@1.0.0` and `DEMO-OSPREY-0001`.
4. **01:30 - Vulnerable symbol:** Show the advisory-mapped `decodeUnsafe` symbol; mapping is not proof of exploitation.
5. **02:00 - Reachability:** Show the supported route-to-call path and separate `NOT_REACHABLE` and `UNKNOWN` cases.
6. **02:30 - Evidence:** Inspect source locations, evidence IDs, provenance, and limitations.
7. **03:00 - Risk:** Explain why missing severity/context evidence leaves risk `UNKNOWN`.
8. **03:30 - Remediation:** Review the proposal for only the temporary manifest/lockfile pair; type `APPROVE` explicitly.
9. **04:15 - Verification:** Show the rescan and narrowly scoped synthetic-fixture `VERIFIED` result.
10. **04:45 - Copilot:** If the authenticated backend is configured, ask it to explain an actual synthetic evidence record. The offline runner does not fake this response.
11. **05:00 - Limitations / close:** State that neither the static path nor fixture verification proves exploitability, runtime use, or production exposure.

## Before -> finding -> evidence -> remediation -> verification

The scan, analysis cases, proposal, apply, and verification are direct calls to the shared Osprey engine. The UI is not populated with fabricated states for this fixture. Copilot is not included in the standalone runner because its question endpoint requires an authenticated backend record; use the separately configured backend only if demonstrating that real API path.

## Safety and limitations

The fixture contains no credentials, personal data, malware, real package, or exploit payload. Registry URLs use the reserved `.invalid` domain and are metadata only; no dependency installation is needed. The fixture deliberately demonstrates synthetic advisory coverage and analyzer behavior, not ecosystem coverage or production security. The demo's `VERIFIED` result is narrow and must not be presented as deployment or runtime verification.

## Manual portfolio screenshots

No screenshots are committed: the UI requires a running authenticated backend, and screenshots from this local environment could expose tokens, personal paths, or local configuration. Capture these manually only with a fresh synthetic workspace and no personal browser profile:

1. **Finding view:** synthetic package/advisory, observed version, severity/risk state, and advisory coverage visible.
2. **Reachability/evidence view:** vulnerable symbol, route-to-call path, evidence IDs, and UNKNOWN/runtime limitation visible.
3. **Remediation view:** proposal scope and explicit approval state; show VERIFIED only after the fixture's actual apply/rescan.
4. **Copilot view:** authenticated synthetic finding context with an evidence-grounded answer; no request headers, API keys, or real workspace paths.

Before staging screenshots, check browser chrome, local usernames, tokens, real repository paths, and non-synthetic data.
