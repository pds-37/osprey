# Osprey Release Demo Video Script

Target runtime: approximately 4–5 minutes. Use the synthetic offline fixture in `docs/DEMO.md`. Do not present its fictional advisory as a real CVE or its scoped verification as deployment verification.

## 0:00–0:35 — The problem

“Dependency scanners are valuable, but a package/version match answers only whether an observed version overlaps an advisory. It does not answer whether supported application code reaches the affected function. Osprey makes that next evidence question explicit.”

## 0:35–1:10 — Scan and package finding

“Here I run Osprey against a small offline fixture. The package and advisory are synthetic. The scanner reports the observed dependency and version separately from advisory coverage, so an unavailable feed is never presented as a clean bill of health.”

## 1:10–1:50 — Symbol and reachability

“The synthetic advisory maps a vulnerable symbol. Osprey parses a bounded subset of the source and shows the route-to-call path it can support. The fixture also includes a non-reachable example and a dynamic case that remains unknown. This is not complete program analysis or exploitability proof.”

## 1:50–2:30 — Evidence and risk

“Each conclusion is accompanied by source, provenance, and limitations. The deterministic risk engine uses supported inputs; missing evidence remains unknown. Evidence hashes help detect tampering, but local SQLite is mutable and does not provide trusted time or independent custody.”

## 2:30–3:30 — Remediation

“Osprey proposes a bounded update to supported npm manifest and lockfile files. The proposal is read-only until an authorized human explicitly approves it. Osprey checks the current inputs and does not invoke npm, lifecycle scripts, or project commands.”

## 3:30–4:05 — Verification

“The demo applies the approved proposal only to a temporary fixture copy, then rescans. The resulting verified state is scoped to deterministic advisory and lockfile conditions. It says nothing about installation, runtime, production deployment, or exploitability.”

## 4:05–4:35 — Copilot

“The optional Copilot can explain an existing evidence record through the authenticated API. It is read-only: the provider can choose among server-authored facts, while the deterministic engine owns risk and workflow state. The offline fixture does not fabricate a Copilot answer.”

## 4:35–5:00 — Limitations and close

“Reachability and runtime evidence are bounded, advisory coverage can be incomplete, Python dependencies are not lockfile-pinned, and seven frontend development advisories remain disclosed. Osprey is a local portfolio project, not a production multi-tenant service. Its goal is to make evidence and uncertainty reviewable before action.”
