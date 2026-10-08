# Osprey Interview Demo Script

Target length: about five minutes. Use the synthetic offline fixture described in docs/DEMO.md. The standalone runner exercises the actual shared scanner and remediation logic; it does not fabricate Copilot state. Show Copilot only through the separately configured authenticated backend.

## 0:00 - Problem

“Package-level scanning tells us that a version overlaps an advisory. It does not show whether supported application code reaches the affected operation. Osprey adds that evidence while keeping gaps visible.”

## 0:30 - Scan

“I’m running the offline fixture. Its package and advisory are synthetic, the cache is isolated, and Osprey does not execute the scanned application.”

## 1:00 - Vulnerable dependency

“This is fictional `demo-codec` version 1.0.0 and synthetic advisory `DEMO-OSPREY-0001`. Version matching identifies the affected package observation.”

## 1:30 - Vulnerable symbol

“The advisory maps `decodeUnsafe`. That is the symbol the source analysis will look for; the mapping alone does not show that the application calls it.”

## 2:00 - Reachability

“This route has a supported static path to the mapped function. The fixture also demonstrates a not-reached case and a dynamic-import case that remains `UNKNOWN`. This is static evidence, not exploit proof.”

## 2:30 - Evidence

“These source locations and evidence records come from the actual scanner output. Hashes help detect record changes, but local SQLite is mutable and does not establish trusted time or chain of custody.”

## 3:00 - Risk

“The deterministic risk engine uses the evidence it has. Because required severity and application-context evidence are absent here, the result remains `UNKNOWN`; Copilot cannot fill those gaps.”

## 3:30 - Remediation

“The proposal is limited to the temporary `package.json` and lockfile. I review it, then explicitly approve. Osprey does not invoke npm or project code.”

## 4:15 - Verification

“The runner rescans the temporary copy. `VERIFIED` here means the supported synthetic advisory/lockfile check passed; it does not mean the package was installed or deployed.”

## 4:45 - Copilot

“The offline fixture does not invent a model answer. With the authenticated backend configured, I can ask the read-only Copilot to explain a real synthetic evidence record; deterministic Osprey state remains authoritative.”

## 5:00 - Limitations / close

“Reachability and runtime evidence are bounded, advisory coverage varies, and this is not a production multi-tenant service. Osprey helps reviewers inspect evidence and uncertainty before approving a scoped change.”
