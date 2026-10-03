# Flagship Demonstration Scenario: The libheif Supply Chain Attack Path

This walkthrough details the canonical supply-chain propagation scenario modeled by GuardianOS v2, illustrating how an upstream memory-corruption vulnerability cascades into production cloud asset exposure and how GuardianOS v2 remediates and verifies the fix.

---

## The Target Vulnerability: CVE-2023-44398

- **Component**: `libheif` (HEIF/AVIF image format library)
- **Vulnerability**: Heap buffer overflow in `libheif/box.cc` during `iloc` box parsing.
- **Impact**: Arbitrary Remote Code Execution (RCE) via malicious `.heic` image uploads.
- **CVSS Score**: 9.8 (Critical)

---

## The Propagation Chain & Real-World Disconnect

```
1. Upstream libheif project: Fix committed in git commit 66f6cfb.
   ↓
2. Security Advisory: CVE-2023-44398 published.
   ↓
3. Linux Distribution: Debian Bookworm releases updated package 1.19.8-1~deb12u1.
   ↓
4. Base Container Image: python:3.11-slim still pins older debian snapshot (1.19.7-1).  <-- BOTTLENECK
   ↓
5. Application Container: Built 2 weeks ago from unpatched base image.
   ↓
6. Production Workload: Runs image-service with libheif 1.19.7 actively exposed in memory.
```

**The Core Insight:**
Even though upstream has fixed the code and Debian has packaged it, the organization's production container remains 100% vulnerable because the base Docker image was not rebuilt.

---

## The Adversary Attack Path

```
[1] Node: node:Internet
    └─ Ingress: POST /upload (Public, Unauthenticated)
[2] Node: node:app-image-service (Discourse image upload handler)
    └─ Invokes: system parser
[3] Node: node:imagemagick (ImageMagick 7.1.1-28)
    └─ Loads dynamic library: libheif.so.1
[4] Node: node:libheif (libheif 1.19.7 - Heap buffer overflow RCE)
    └─ Attacker achieves Remote Code Execution within pod
[5] Node: node:k8s-service-account (Attached AWS IAM role: ImageServiceRole)
    └─ IAM Permissions: s3:PutObject, s3:GetObject, s3:ListBucket
[6] Node: node:s3-customer-media (s3://customer-media-production)
    └─ RESULT: Exfiltration and tampering with customer production media
```

---

## The 11-Stage Resolution Workflow

### 1. Ingest Multi-Tier SBOM
- Ingests application container, Debian OS packages, and dynamic dependencies.
- Distinguishes 3 states:
  - Declared: `package.json` / `requirements.txt`
  - Installed: Debian packages in container image filesystem
  - Running: Active memory workloads

### 2. Correlate Vulnerability
- Deterministic matcher maps `libheif 1.19.7` to `CVE-2023-44398`.
- Flags fixed version: `1.19.8`.

### 3. Detect Upstream Fix
- Heuristic commit classifier inspects upstream commit `66f6cfb` in `strukturag/libheif`.
- Detects signals: `integer conversion`, `bounds calculation`, `memory allocation`.
- Classifies as: `CONFIRMED_VULNERABILITY_FIX` with 95% confidence.

### 4. Patch Propagation Analysis
- Checks 6-stage pipeline.
- Marks Step 1-3 as COMPLETED.
- Identifies Step 4 (`BASE_IMAGE_REBUILD`) as the active bottleneck.
- Verdict: `PRODUCTION EXPOSED`.

### 5. Runtime Exposure Profiling
- Inspects network ingress table.
- Flags `POST /upload` as internet-accessible and unauthenticated (`auth_required: false`).
- Classifies `libheif` parser role as `PRIMARY_INGRESS_PARSER`.

### 6. Graph Attack Path Traversal
- Traverses directed graph from `node:Internet` to `node:s3-customer-media`.
- Computes confidence: 95%.
- Status: `OPEN`.

### 7. Contextual Risk Scoring
- Composite formula calculates risk score: **96.5 / 100 (CRITICAL)**.
- Explains 4 contributing factors: CVSS severity, runtime ingress reachability, cloud privilege escalation, and direct attack path existence.

### 8. AI Analyst Threat Synthesis
- Generates evidence-backed narrative citing graph nodes.
- Strict prompt-injection defense sanitizes inputs and untrusted metadata.

### 9. Propose Remediation PR
- Generates non-destructive Git pull request.
- Produces unified diff updating `Dockerfile`:
  ```diff
  --- Dockerfile
  +++ Dockerfile
  @@ -8,3 +8,3 @@
  -RUN apt-get update && apt-get install -y libheif1=1.19.7-1
  +RUN apt-get update && apt-get install -y libheif1=1.19.8-1~deb12u1
  ```

### 10. Human Approval Gate
- Pull request proposal enters `PENDING_APPROVAL` status.
- Zero autonomous destruction: Production is never modified automatically.
- Engineer `secops-lead@guardian.internal` reviews diff and grants authorization.
- Status transitions to `APPROVED`.

### 11. Verification Rescan & Closure
- CI/CD builds updated image and deploys.
- GuardianOS initiates post-deployment verification rescan.
- Confirms `libheif` running in production is now version `1.19.8`.
- Confirms `CVE-2023-44398` is resolved.
- Confirms Attack Path transitions to **CLOSED**.
