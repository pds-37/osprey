# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-04

### Added
- **Core CLI**:
  - `osprey scan [PATH]` with rich prioritized terminal output (10-15 lines summary), `--detail`, `--json`, `--sarif`, `--sbom`, `--offline`, and `--fail-on` options.
  - `osprey explain <id>` displaying complete deterministic audit chain, firing risk rules, package-level exposure, and minimal safe version recommendations.
  - `osprey init` generating starter `osprey.yaml` with commented service exposure overrides.
  - `osprey demo` bundled offline walkthrough against a known-vulnerable sample application (`examples/vulnerable-app`).
  - `--version` / `-v` flag and `--debug` flag for detailed stack trace diagnostics on demand while maintaining clean user-facing error messages by default.
- **Manifest Parsers**:
  - NPM parser supporting `package.json` and `package-lock.json` (v2 and v3 format) with devDependency detection.
  - PyPI parser supporting `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, and `poetry.lock`.
  - Docker parser extracting base images (`FROM`), exposed ports (`EXPOSE`), build contexts, and copied files from `Dockerfile` and `docker-compose.yml`.
- **Exposure Attribution Engine**:
  - Service container context mapping linking manifest files to owning services via longest-prefix build context matching and Dockerfile `COPY`/`ADD` tracking.
  - Honest package-level exposure classification: `public (inferred)`, `internal (inferred)`, `dev-only`, and `unknown` (guaranteed fallback if unproven, never falsely tagging internal components as public).
  - Configuration override support via `osprey.yaml` with `declared` confidence.
- **Deterministic Evidence-Aware Risk**:
  - Shared CLI/backend engine returns a normalized score, level, factors, explanation, and `ACT NOW`, `PLAN`, `MONITOR`, `IGNORE`, or `UNKNOWN` decision.
  - Missing EPSS, KEV, version, exposure, or reachability evidence remains unavailable and is reported as a limitation; the fixed weights are not an industry standard.
- **Upstream Fix Tracking**:
  - Minimal safe version calculation derived from OSV vulnerability fixed ranges.
  - Roadmap placeholders for future multi-stage lifecycle tracking (distro, base image, lockfile, production).
- **Vulnerability Intelligence & Caching**:
  - OSV API query batch client with automatic chunking and timeout handling.
  - Optional FIRST EPSS and CISA KEV enrichment with soft-fail degradation.
  - Local SQLite/JSON response cache in `~/.cache/osprey` with 24-hour TTL and complete offline scan support.
- **Compliance & CI Export**:
  - SARIF 2.1.0 export for GitHub Code Scanning and security tab integration.
  - CycloneDX 1.5 JSON Software Bill of Materials (SBOM) export using standard purl identifiers.
  - GitHub Action composite wrapper (`action.yml`).
  - Comprehensive offline unit test suite across parsers, exposure attribution, risk tiers, and CLI exit codes.
