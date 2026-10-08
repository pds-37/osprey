# Screenshot Plan

Capture only from a fresh synthetic workspace and authenticated test account. Never include real project names, personal paths, browser profiles, request headers, tokens, API keys, or production data. Do not fabricate UI state; each visible state must be produced by Osprey.

## 1. Finding / Threat Center

- **Screen:** Finding list/detail in Threat Center.
- **Purpose:** Show the affected package/version, advisory coverage, severity and deterministic risk state.
- **Must be visible:** Fictional fixture name, finding identity, coverage status, risk/unknown explanation.
- **Must be hidden:** User identity, local paths, auth/session details, unrelated findings.
- **Crop:** Main panel from title through evidence/coverage summary; exclude browser chrome and sidebars with account details.

## 2. Vulnerable symbol + reachability

- **Screen:** Finding's symbol/reachability detail.
- **Purpose:** Show the mapped function and bounded route-to-call path.
- **Must be visible:** Symbol, source locations, path edges, result (`REACHABLE`, `NOT_REACHABLE`, or `UNKNOWN`), limitations.
- **Must be hidden:** Real source contents, home-directory paths, unrelated repository names.
- **Crop:** Graph plus the result/limitations panel; keep labels legible.

## 3. Evidence + remediation + verification

- **Screen:** Evidence record and remediation workflow.
- **Purpose:** Show provenance, approval gate, scoped files, and the actual verification state.
- **Must be visible:** Evidence IDs/hashes as generated, proposal file scope, explicit approval state, rescan result and scope note.
- **Must be hidden:** SQLite location, real workspace paths, credentials, unapproved state presented as applied.
- **Crop:** Workflow timeline with evidence summary; include the narrow verification disclaimer.

## 4. Copilot explanation

- **Screen:** Copilot drawer for an existing synthetic finding.
- **Purpose:** Show an explanation grounded in deterministic evidence.
- **Must be visible:** The question, evidence references/fact keys, read-only status, uncertainty/limitations.
- **Must be hidden:** Provider API key, request/response headers, system prompt, personal account details, external provider dashboard.
- **Crop:** Drawer content and finding context only; redact browser chrome and network tooling.
