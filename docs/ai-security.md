# GuardianOS v2 — AI Security & Prompt Injection Defense

## Principles
1. **AI is Never the Source of Truth**: Deterministic security data (CVE databases, package versions, reachability graphs) constitutes the factual bedrock. AI is utilized solely for contextual reasoning, explanation synthesis, and code remediation proposals.
2. **Untrusted Data Boundaries**: Upstream commit messages, security advisories, release notes, and repository READMEs are untrusted data strings. They must never be interpolated directly into system instructions.
3. **Structured Tool Calling**: The AI Analyst only has access to read-only retrieval tools to query the Knowledge Graph, vulnerability tables, and inventory.
4. **Mandatory Evidence Citations**: Every AI assertion must cite verifiable graph node IDs, CVE numbers, or commit SHAs.

```
+-------------------------------------------------------------+
|                      USER INQUIRY                           |
|       "Why is this libheif vulnerability critical?"        |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|                     AI SECURITY ANALYST                     |
|  Calls Tools:                                               |
|  - get_component_lineage("pkg:deb/debian/libheif@1.19.7")   |
|  - get_exposure_profile("media-service")                   |
|  - get_attack_paths("Internet", "s3://customer-data")       |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|                      GROUNDED SYNTHESIS                     |
|  "libheif 1.19.7 is running in prod-media-processor.       |
|   It is reached via POST /upload without auth.             |
|   Exploitation gives container access with IAM permissions  |
|   to customer S3 bucket. (Confidence: 0.95)"                |
+-------------------------------------------------------------+
```
