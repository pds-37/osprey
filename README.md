# GuardianOS v2 — Supply Chain Intelligence & Attack Path Security Platform

> **AI-Native Security Control Plane for Enterprise Software Supply Chains**

GuardianOS v2 is an advanced Software Supply Chain Intelligence and Attack Path Security Platform. Rather than operating as another superficial CVE vulnerability scanner, GuardianOS v2 correlates software supply-chain intelligence with runtime exposure, cloud identity, agent permissions, and adversary attack paths to answer the question:

> *"A security-relevant change or vulnerability was discovered in a component that your environment depends on. Are you actually affected, where is the vulnerable component running, can an attacker reach it, what could they access after exploitation, and what should you do?"*

---

## 🏗️ Core Architecture & Pipeline

```
DETECT ➔ UNDERSTAND ➔ CORRELATE ➔ VERIFY EXPOSURE ➔ BUILD ATTACK PATH ➔ PRIORITIZE RISK ➔ RECOMMEND REMEDIATION ➔ HUMAN APPROVAL ➔ REMEDIATE ➔ VERIFY
```

GuardianOS v2 implements the following architectural layers:

1. **Inventory & SBOM Normalization Engine**: Multi-format ingestion (CycloneDX 1.4/1.5, SPDX 2.2/2.3, Syft) tracking dependencies across three distinct states:
   - **Declared Dependency** (manifest / lockfile)
   - **Installed Dependency** (filesystem / container image)
   - **Running Dependency** (active production workload)
2. **Deterministic Knowledge Graph**: Built on dual-mode graph architecture (in-memory NetworkX with Neo4j driver compatibility), modeling transitive dependency chains, container layers, network ingress routes, host workloads, service accounts, and cloud resources.
3. **Upstream Change Monitor**: Heuristic analysis on upstream commits, pull requests, and security fixes prior to formal CVE publication, identifying critical signals such as bounds checking, integer overflow safeguards, and memory allocation protections.
4. **Patch Propagation Tracker**: 6-stage lifecycle tracking across:
   `UPSTREAM_FIX` ➔ `SECURITY_ADVISORY` ➔ `DISTRIBUTION_PACKAGE` ➔ `BASE_IMAGE_REBUILD` ➔ `APPLICATION_IMAGE_REBUILD` ➔ `PRODUCTION_DEPLOYMENT`
   Pinpoints bottlenecks explaining why upstream fixes have not reached production.
5. **Runtime Exposure Analyzer**: Correlates runtime ingress (`POST /upload`), authentication posture (Unauthenticated vs Authenticated), public IP routing, and parser roles.
6. **Attack Path Engine**: Deterministic graph traversals connecting external entrypoints to high-value cloud assets (e.g. AWS S3 buckets, cloud databases, service account tokens).
7. **Contextual Risk Engine**: Explainable composite risk scoring (0–100) factoring CVSS, runtime reachability, privilege scope, and attack path depth.
8. **Evidence-Grounded AI Security Analyst**: Cites authoritative graph and vulnerability nodes with strict prompt-injection defenses (input sanitization and system boundaries).
9. **Remediation & Human Approval Gate**: Generates pull request unified diffs against `Dockerfile` / manifests. Implements strict zero-autonomous-destruction approval gates and automated post-fix verification rescans.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ (tested on Python 3.14.3)
- Node.js 18+ (tested on Node.js v24.14.0)

### 1. Backend Setup & Test Suite
```bash
# Run the complete test suite (35 unit & integration tests)
python run_tests.py

# Start the FastAPI backend server
python -m uvicorn guardianos.api.app:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at: `http://localhost:8000/api/docs`.

### 2. Frontend Setup & Build
```bash
cd frontend
npm install
npm run build
npm run dev
```
The React 18 / Tailwind CSS dashboard will be available at: `http://localhost:5173`.

---

## 🔬 Flagship End-to-End Demonstration Scenario

GuardianOS v2 includes a built-in interactive end-to-end demonstration scenario modeling the real-world **libheif / ImageMagick** vulnerability chain:

```
Internet (External Adversary)
   ↓ [Unauthenticated HTTP POST /upload]
Discourse / Image Service (Web Application)
   ↓ [Invokes command / native binding]
ImageMagick 7.1.1-28 (Debian Package)
   ↓ [Shared Library Linking libheif.so.1]
libheif 1.19.7 (Vulnerable: CVE-2023-44398 Heap Buffer Overflow RCE)
   ↓ [Container Escapes / Compromises Workload]
K8s ServiceAccount (IAM Role)
   ↓ [s3:PutObject / s3:GetObject]
s3://customer-media-production (High-Value Target Cloud Asset)
```

### The 11-Stage Verification Walkthrough:
1. **Multi-Tier SBOM Ingestion**: Ingests container image, Debian OS packages, and `libheif 1.19.7`.
2. **Vulnerability Correlation**: Deterministically matches `CVE-2023-44398` (CVSS 9.8 Critical).
3. **Upstream Fix Detection**: Identifies upstream commit `66f6cfb` fixing integer conversion in `libheif/box.cc`.
4. **Patch Propagation Tracking**: Analyzes the 6-stage lifecycle, detecting a bottleneck at `BASE_IMAGE_REBUILD` (Debian fixed, base image not rebuilt).
5. **Runtime Exposure Assessment**: Confirms `POST /upload` endpoint is public and unauthenticated.
6. **Attack Path Traversal**: Constructs deterministic graph path from `Internet` to `s3://customer-media-production`.
7. **Contextual Risk Scoring**: Assigns composite risk score of **96.5 (CRITICAL)**.
8. **AI Analyst Synthesis**: Generates evidence-grounded threat narrative with citation badges.
9. **Remediation PR Generation**: Proposes non-destructive Git diff bumping `libheif=1.19.8` in `Dockerfile`.
10. **Human Approval Gate**: SecOps engineer reviews and authorizes PR.
11. **Verification Rescan**: Rescans production environment, confirms updated library version, and proves **Attack Path CLOSED**.

You can trigger this demonstration anytime from the web UI banner with 1 click, or via API:
```bash
curl -X POST http://localhost:8000/api/v1/demo/run
```

---

## 📂 Project Structure

```
.
├── backend/
│   └── guardianos/
│       ├── ai/             # AI Analyst, vector store & prompt injection shields
│       ├── api/            # FastAPI routers (v1 endpoints & app factory)
│       ├── core/           # Configuration, logging, models & DB engines
│       ├── demo/           # Flagship 11-step end-to-end scenario
│       ├── exposure/       # Runtime exposure analyzer & ingress profiling
│       ├── graph/          # In-memory NetworkX & Neo4j graph stores
│       ├── intelligence/   # CVE matching, version ranges & feed registry
│       ├── inventory/      # CycloneDX, SPDX, Syft parsers & normalizer
│       ├── paths/          # Adversary attack path graph traversal engine
│       ├── propagation/    # 6-stage patch propagation lifecycle tracker
│       ├── remediation/    # PR diff generation, approval gate & rescan
│       ├── risk/           # Contextual risk engine & composite scoring
│       └── upstream/       # Heuristic commit & security signal analyzer
├── frontend/
│   ├── src/
│   │   ├── components/     # UI Views (Inventory, Graph, Attack Paths, Propagation, AI, PRs, Demo)
│   │   ├── api.ts          # REST client
│   │   ├── types.ts        # TypeScript data contracts
│   │   └── App.tsx         # Root application
├── docs/                   # Deep architecture & threat model specifications
├── tests/                  # Unit and integration test suite (35 tests)
├── run_tests.py            # Isolated test runner
└── pytest.ini              # Pytest configuration
```

---

## 🔒 Security Principles

- **Deterministic Truth**: AI is never the authoritative source of truth. AI assists with reasoning, semantic correlation, and explanation; the deterministic graph and vulnerability feeds determine vulnerabilities and exposure.
- **Zero Autonomous Production Modification**: Remediation actions follow strict Human-in-the-Loop gates (Detection ➔ Recommendation ➔ PR ➔ Human Approval ➔ CI/CD ➔ Deployment ➔ Verification).
- **Prompt Injection Defense**: All user inputs and untrusted package metadata are sanitized before LLM context ingestion.
- **Immutable Audit Logging**: All SBOM uploads, PR approvals, and verification rescans are recorded in persistent audit event logs.
