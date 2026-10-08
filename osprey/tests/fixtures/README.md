# Test Fixtures & Threat Intelligence Cache

## Overview

This directory contains test fixtures used to support reproducible offline testing and CI smoke verification for Osprey.

## Capture Information

- **Capture Date**: `2026-10-04`
- **Fixture File**: `cache/intel_cache.db` (SQLite database)
- **Target Application**: `examples/vulnerable-app` pinned dependencies

## Public Advisory Data Attribution

The threat intelligence records stored in `cache/intel_cache.db` consist exclusively of **publicly available security advisory and vulnerability scoring metadata** collected from open authoritative feeds:

1. **OSV (Open Source Vulnerabilities)**
   - Source: [`https://api.osv.dev/v1/querybatch`](https://api.osv.dev)
   - Scope: Public vulnerability records and upstream fix version ranges.
2. **FIRST EPSS (Exploit Prediction Scoring System)**
   - Source: [`https://api.first.org/data/v1/epss`](https://www.first.org/epss/)
   - Scope: Public exploit probability scores for CVE identifiers.
3. **CISA KEV (Known Exploited Vulnerabilities Catalog)**
   - Source: [`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`](https://www.cisa.gov)
   - Scope: Public list of actively exploited vulnerabilities.

## Privacy & Safety Notice

- **No Proprietary Data**: Contains no proprietary, internal, or customer code or identifiers.
- **No Secrets**: Contains no API keys, credentials, tokens, or environment variables.
- **Usage**: Intended strictly for automated offline testing (`pytest`, CI workflows, and `osprey demo --offline`).
