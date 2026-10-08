# Flagship Demo Fixture

The optional `run_flagship_demo` scenario is a seeded UI/API demonstration, not a scan of the user's cloud or production environment. It inserts fictional libheif/ImageMagick inventory, endpoint configuration, upstream commit text, IAM/S3 graph nodes, patch stages, and a simulated remediation lifecycle.

The response marks the scenario as `DEMO_FIXTURE_COMPLETED` and `SIMULATED_FIXTURE_DATA_NOT_LIVE_OBSERVATIONS`. It exists to show how a possible evidence workflow could look, not to support security conclusions about a real application.

Use the demo only when `ENABLE_DEMO_FIXTURES=true` and through its authenticated, admin-protected API route. Normal workspace scans do not inherit its records. Do not export fixture paths, risk scores, deployment claims, or remediation closure as real findings.

For evidence-backed analysis, use a real SBOM/workspace observation and the static reachability endpoint. Its result is limited to submitted source and advisory-provided vulnerable symbols.
