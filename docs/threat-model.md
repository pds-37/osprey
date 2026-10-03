# GuardianOS v2 — Threat Model & Security Architecture

## Assets Under Protection
1. Production workloads and containerized services.
2. IAM identities, cloud service accounts, and developer tokens.
3. Upstream software dependencies and software bill of materials (SBOM).
4. AI agent execution environments and tool capabilities.

---

## Attacker Entry Points
- **Internet Ingress**: Public unauthenticated HTTP endpoints (e.g., file upload handlers, webhook listeners).
- **Supply Chain Compromise**: Upstream malicious release, typosquatting, dependency confusion.
- **Compromised Developer Identity**: Leaked PAT or GitHub account access.
- **Transitive Library Exploit**: Vulnerability buried multiple layers below direct application code (e.g., Application -> ImageMagick -> libheif -> memory corruption).

---

## Defensive Boundary Safeguards
- **Untrusted Input Isolation**: All external advisories, commit diffs, and SBOM files are parsed strictly as untrusted data strings.
- **Prompt Injection Immunity**: AI prompts encapsulate external data in sanitized demarcated blocks. The AI analyst is restricted to calling explicit deterministic APIs to query the graph.
- **Human Approval Gate**: Zero autonomous destructive changes to production code or running infrastructure.
- **Tamper-Evident Audit Logging**: Every ingestion, risk recalculation, PR generation, and approval is recorded in an immutable audit ledger.
