# GuardianOS v2 — REST API Reference

All APIs are versioned under `/api/v1`.

## Endpoints

### Operational
- `GET /health` — Service health and version status.
- `GET /ready` — Readiness check verifying database and graph connections.
- `/api/docs` — Interactive OpenAPI Swagger UI documentation.

### SBOM Management
- `POST /api/v1/sboms/upload` — Ingest raw JSON payload (CycloneDX, SPDX, Syft).
- `POST /api/v1/sboms/upload-file` — Ingest SBOM file upload multipart form.
- `GET /api/v1/sboms` — List all ingested SBOM documents with summary counts.
- `GET /api/v1/sboms/{id}` — Get single SBOM document metadata.

### Software Components & Lineage
- `GET /api/v1/components` — Filterable list of normalized software components (`ecosystem`, `search`, `application`).
- `GET /api/v1/components/detail?purl={purl}` — Retrieve specific component by PURL.
- `GET /api/v1/components/lineage?purl={purl}` — Extract full ancestry chain connecting application/container to the target component.

### Knowledge Graph
- `GET /api/v1/graph/data` — Retrieve graph nodes and edges styled for interactive visualization.
- `GET /api/v1/graph/subgraph?node_id={id}&depth={depth}` — Retrieve neighborhood graph around specific node.
- `POST /api/v1/graph/paths` — Find all simple paths between a source and target node.

### Audit
- `GET /api/v1/audit/events` — Retrieve tamper-evident operational log records.
