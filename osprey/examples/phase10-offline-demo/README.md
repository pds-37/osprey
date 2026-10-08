# Offline Phase 10 Demo Fixture

This is fictional package metadata and harmless source code. `DEMO-OSPREY-0001` is a synthetic advisory seeded at runtime by the demo script. It is not a real CVE, advisory, package, exploit, or security claim about a third-party project. The scanned code is parsed as text and is never executed.

Run from the Osprey repository root with the configured `.venv`:

```powershell
python .\osprey\examples\phase10-offline-demo\run_demo.py
```

The runner copies the fixture to a temporary directory, creates a temporary isolated OSV cache, scans offline, prints actual scanner evidence and deterministic risk, shows separate reachable / not-reached / unknown parser cases, then asks for the exact word `APPROVE` before applying an eligible change to that temporary copy. It rescans and prints the real verification state. Declining approval leaves the original fixture unchanged. Temporary files are removed when the script exits.
