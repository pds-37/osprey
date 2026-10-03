# GuardianOS v2 — System Architecture

## Overview
GuardianOS v2 is an AI-native Software Supply Chain Intelligence and Attack Path Security Platform. Rather than operating as an isolated CVE scanner, GuardianOS correlates multi-format SBOMs, upstream repository signals, container layers, runtime network exposure, and IAM permissions into a unified Knowledge Graph to discover, prioritize, and remediate exploitable attack paths.

```mermaid
flowchart TD
    subgraph External Sources
        GH[GitHub Repositories]
        OSV[OSV Database]
        NVD[NVD & GHSA]
        DEB[Debian / Distro Trackers]
    end

    subgraph Ingestion Layer
        S1[CycloneDX JSON 1.4/1.5]
        S2[SPDX JSON 2.2/2.3]
        S3[Syft Container JSON]
        P[Multi-format SBOM Normalizer]
        S1 --> P
        S2 --> P
        S3 --> P
    end

    subgraph Storage & Graph
        P --> DB[(PostgreSQL / SQLite\nAuthoritative Inventory)]
        P --> KG[(Neo4j / NetworkX\nKnowledge Graph)]
    end

    subgraph Security Engines
        KG --> EX[Exposure Analyzer]
        KG --> AP[Attack Path Engine]
        KG --> RK[Contextual Risk Engine]
        GH --> UC[Upstream Change Monitor]
        DEB --> PT[Patch Propagation Tracker]
    end

    subgraph Remediation & AI
        AP --> AI[Evidence-Grounded AI Analyst]
        RK --> RM[Remediation Engine]
        RM --> PR[PR Generator & Human Approval]
        PR --> VF[Verification Engine]
    end
```

## Core Tenets
1. **Never Just a CVE Dashboard**: Vulnerability data is correlated with container hierarchies, runtime ports, unauthenticated endpoints, and lateral privileges.
2. **Three Dependency States**: Always distinguishes between:
   - `DECLARED`: Manifest/lockfile definition.
   - `INSTALLED`: Filesystem / container image package.
   - `RUNNING`: Actively executing production workload.
3. **AI Grounding**: Deterministic graph traversals and structured database records are the sole source of truth. LLMs reason over retrieved facts and cite explicit node IDs.
4. **Human in the Loop**: Remediation tasks generate verifiable Pull Requests requiring human approval prior to deployment and post-fix verification.
