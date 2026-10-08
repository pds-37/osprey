# API Reference

This reference was checked against the FastAPI route declarations and generated OpenAPI schema on 2026-10-09. The live schema at `/api/docs` is the authoritative source for exact Pydantic field definitions and examples. Business endpoints use `/api/v1`; the operational health routes and documentation are mounted separately.

## Authentication and common responses

`GET /health`, `GET /ready`, the OpenAPI pages, `POST /api/v1/auth/token`, and the two read-only advisory catalog endpoints are public in the current implementation. Other listed endpoints require `Authorization: Bearer <JWT>`.

Tokens are issued only for configured accounts in `AUTH_USERS_JSON`; there is no user-management API. Roles are `viewer`, `security_engineer`, and `admin`. `SecuredAPIRouter` requires viewer for reads and security engineer for writes by default; approval, clear, and demo-run operations require admin. Endpoint-specific behavior is called out below. Several legacy/global services require a single configured organization and return `409` when that condition is not met. This is not a general-purpose multi-tenant deployment.

Typical errors: `401` missing/invalid token or login, `403` insufficient role, `404` missing or out-of-scope object (where handlers intentionally avoid revealing cross-org existence), `409` invalid workflow/state or unsupported multi-organization context, `413` request body over configured limit (10 MiB default), and `422` FastAPI request validation. Some legacy routes return service-specific `400`/`404`; unhandled internal errors are not a supported response contract. Query bounds and request models are shown in OpenAPI.

## Operational and authentication endpoints

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `GET /health` | Process/version/environment health | Public | None | Status object | — |
| `GET /ready` | Reports configured storage adapter labels; does not probe database health | Public | None | Readiness metadata | — |
| `POST /api/v1/auth/token` | Issue token for configured account | Public; valid configured credentials required | OAuth2 form: `username`, `password` | `access_token`, `token_type` | `400` invalid credentials; `422` malformed form |

## Inventory, evidence, and analysis

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `POST /api/v1/analysis/reachability` | Analyze a stored finding against caller-supplied source text | Security engineer; finding must belong to user's organization | JSON `finding_id`, `source_files` mapping | Reachability status/path/evidence/limitations | `404` finding not in scope; `413`/`422` invalid or over-bound bundle |
| `GET /api/v1/evidence/{evidence_id}` | Read one integrity-checked evidence record | Viewer; evidence must be referenced by an in-scope finding/workflow | Path ID | Evidence envelope and integrity status | `404` unknown, malformed, or out of scope |
| `POST /api/v1/sboms/upload` | Ingest SBOM JSON | Security engineer; attributed to token organization | JSON SBOM and optional metadata | `201` ingestion result | `400` unsupported/invalid SBOM; `413`/`422` |
| `POST /api/v1/sboms/upload-file` | Ingest uploaded SBOM file | Security engineer; attributed to token organization | Multipart file and form metadata | `201` ingestion result | `400` invalid/unsupported file; `413`/`422` |
| `GET /api/v1/sboms` | List organization-scoped SBOM metadata | Viewer; organization filtered server-side | None | SBOM documents | — |
| `GET /api/v1/sboms/{sbom_id}` | Read one SBOM record | Viewer; organization checked | Path ID | SBOM document | `404` absent/out of scope |
| `POST /api/v1/sboms/clear` | Clear local inventory and derived records | Admin; single-organization context required | None | Clear result | `409` multi-org context |
| `POST /api/v1/sboms/scan-local-manifests` | Scan a relative workspace under configured `WORKSPACE_ROOT` | Security engineer; single mapped organization required | JSON workspace path | `201` ingestion/findings summary | `400`/`404`/`409` invalid or out-of-root workspace; `413`/`422` |
| `GET /api/v1/components` | List/filter component observations | Viewer; organization filter | Query: `ecosystem`, `search`, `application`, bounded `limit` | Component list | `422` invalid filters |
| `GET /api/v1/components/detail` | Read component by PURL | Viewer; organization checked | Query `purl` | Component | `404` not found/in scope |
| `GET /api/v1/components/lineage` | Read graph lineage for a component | Viewer; single-org context | Query `purl` | Lineage object | `404`, `409` |

Reachability request example:

```json
{
  "finding_id": "finding-id",
  "source_files": {
    "src/handler.py": "@router.post('/decode')\ndef decode(req):\n    return codec.decode(req.body)\n"
  }
}
```

The API limits source bundles to 500 files, 1 MiB per file, and 10 MiB total, with supported extensions and relative paths. `NOT_REACHABLE` is scoped to the supplied bundle and supported syntax; missing symbols, routes, or complete parsing produce `UNKNOWN`.

## Findings, risk, and graph

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `GET /api/v1/vulnerabilities` | List findings | Viewer; findings filtered by organization | Optional query `application`, `severity` | Finding list | `422` invalid query |
| `POST /api/v1/vulnerabilities/scan` | Match current inventory to advisories | Security engineer; result filtered by organization | None | Finding list | `409` service/state conflict |
| `GET /api/v1/vulnerabilities/advisories` | List configured advisory catalog | Public; catalog only, not user finding data | None | Advisory list | — |
| `GET /api/v1/vulnerabilities/advisories/{vuln_id}` | Read one catalog advisory | Public; catalog only | Path advisory ID | Advisory | `404` unknown advisory |
| `GET /api/v1/vulnerabilities/findings/{finding_id}` | Read finding details | Viewer; same organization required | Path finding ID | Finding | `404` absent/out of scope |
| `GET /api/v1/risks` | List contextual risk results | Viewer; single-org context | Optional query `level` | Risk list | `422`, `409` |
| `GET /api/v1/risks/summary` | Aggregate risk summary | Viewer; single-org context | None | Summary | `409` |
| `POST /api/v1/risks/evaluate` | Recalculate risk deterministically | Security engineer; single-org context | None | Risk list | `409` |
| `GET /api/v1/graph/data` | Read bounded graph view | Viewer; single-org context | Optional bounded `limit` | Graph nodes/edges | `422`, `409` |
| `GET /api/v1/graph/subgraph` | Read bounded subgraph | Viewer; single-org context | `node_id`, bounded `depth` | Subgraph | `404`, `422`, `409` |
| `POST /api/v1/graph/paths` | Query paths in the current graph | Security engineer; single-org context | JSON path query model | Path list | `422`, `409` |

## Exposure, upstream, propagation, and attack paths

These adapter services are single-organization compatibility features; their router checks reject ambiguous multi-organization context. They store user-supplied or heuristic records, not cloud-discovered truth.

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `GET /api/v1/exposure/endpoints` | List endpoint assertions | Viewer; single-org context | None | Endpoint profiles | `409` |
| `POST /api/v1/exposure/endpoints` | Record endpoint assertion | Security engineer; single-org context | JSON endpoint profile | `201` profile | `422`, `409` |
| `GET /api/v1/exposure/{component_name}` | Read exposure profile | Viewer; single-org context | Path package name | Exposure profile | `404`, `409` |
| `GET /api/v1/upstream-changes` | List supplied upstream-change records | Viewer; single-org context | Optional component filter | Commit records | `409` |
| `POST /api/v1/upstream-changes/analyze` | Classify and ingest supplied commit metadata | Security engineer; single-org context | JSON commit metadata | `201` record | `422`, `409` |
| `GET /api/v1/upstream-changes/{sha}` | Read one supplied commit record | Viewer; single-org context | Path SHA | Commit record | `404`, `409` |
| `GET /api/v1/patches/propagation` | List propagation records | Viewer; single-org context | Optional component filter | Record list | `409` |
| `POST /api/v1/patches/evaluate` | Re-evaluate stored propagation state | Security engineer; single-org context | None | Record list | `409` |
| `GET /api/v1/patches/propagation/{component_name}` | Read one component's propagation | Viewer; single-org context | Path component name | Record | `404`, `409` |
| `GET /api/v1/attack-paths` | List attack-path records | Viewer; single-org context | Optional status filter | Path list | `409` |
| `POST /api/v1/attack-paths/recalculate` | Recalculate from current local evidence | Security engineer; single-org context | None | Path list | `409` |
| `GET /api/v1/attack-paths/{path_id}` | Read one path record | Viewer; single-org context | Path ID | Path record | `404`, `409` |

## Copilot and legacy analyst routes

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `POST /api/v1/copilot/query` | Ask a bounded question about one organization-scoped finding | Viewer; object organization is checked server-side | JSON `finding_id`, `question` (max 2,000 chars) | Osprey-rendered claims, evidence IDs, unknowns and limits | `404` out of scope; `429` per-process rate limit; `422` bounds |
| `POST /api/v1/ai/analyze` | Deterministic evidence summary compatibility route | Viewer; single-org context | JSON analysis request model | Analysis report | `422`, `409` |
| `GET /api/v1/ai/explain/{component_name}` | Read deterministic component explanation | Viewer; single-org context | Path component name | Analysis report | `404`, `409` |

Copilot writes only safe audit metadata, not findings, risk, or remediation. Optional provider failure or malformed output uses deterministic fallback. See [AI Security](ai-security.md).

## Remediation

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `POST /api/v1/remediation/proposals` | Fresh offline scan and read-only proposal creation | Security engineer; workspace constrained under configured root; organization checked | JSON `finding_id`, relative `workspace` | `201` persisted proposal/state | `404`, `409` stale/out-of-root/unsupported context, `422` |
| `GET /api/v1/remediation/proposals/{proposal_id}` | Read proposal | Authenticated owner or same-org admin | Path proposal ID | Proposal and state | `404` missing/out of scope |
| `POST /api/v1/remediation/proposals/{proposal_id}/approve` | Record explicit approval | Admin; owner/org policy enforced | Path proposal ID; empty body | Approval event/state | `404`, `409` invalid/stale state |
| `POST /api/v1/remediation/proposals/{proposal_id}/apply` | Apply approved npm metadata proposal and rescan | Admin; workspace/root/object checks | JSON relative `workspace` | Apply hashes, post-scan and verification | `404`, `409` stale/replay/unsafe path/state, `422` |
| `GET /api/v1/remediation/proposals/{proposal_id}/status` | Read workflow state | Authenticated owner or same-org admin | Path proposal ID | Status object | `404` missing/out of scope |
| `GET /api/v1/remediation/proposals/{proposal_id}/verification` | Read verification output | Authenticated owner or same-org admin | Path proposal ID | Verification object | `404` missing/out of scope |
| `GET /api/v1/remediation/tasks` | Legacy recommendation list (deprecated) | Viewer; single-org context | Optional status | Task list | `409` |
| `POST /api/v1/remediation/tasks/{task_id}/approve` | Legacy approval record (deprecated) | Admin; single-org context | Path task ID | Task record | `404`, `409` |
| `POST /api/v1/remediation/tasks/{task_id}/verify` | Legacy inventory recheck (deprecated) | Security engineer; single-org context | Path task ID | Task record | `404`, `409` |
| `POST /api/v1/remediation/generate` | Generate legacy recommendations (deprecated) | Security engineer; single-org context | None | Task list | `409` |

The legacy task routes do not modify workspace files. The authoritative proposal path supports only bounded npm manifest/lockfile operations; no npm, shell, project code, or lifecycle script is run. `VERIFIED` is limited to the documented post-scan/advisory condition.

## Demo and audit

| Method and path | Purpose | Authentication / authorization | Request | Success response | Additional errors |
|---|---|---|---|---|---|
| `POST /api/v1/demo/run` | Run explicitly enabled simulated backend fixture | Admin; single-org context and `ENABLE_DEMO_FIXTURES=true` | None | Demo summary | `403` disabled; `409` |
| `GET /api/v1/demo/status` | Read demo fixture status | Viewer; single-org context | None | Demo status | `409` |
| `GET /api/v1/audit/events` | List bounded local audit events | Viewer; single-org context | Optional bounded `limit` | Audit event list | `422`, `409` |

## Evidence response semantics

Evidence reads include evidence and record hashes plus `integrity_status`. `VERIFIED` means the stored envelope matched its hash when checked; `MISMATCH` indicates detected tampering; legacy records without the envelope hash are `UNVERIFIED_LEGACY`. SQLite is mutable, so these statuses do not establish immutable storage, trusted time, source authenticity, or independent custody.
