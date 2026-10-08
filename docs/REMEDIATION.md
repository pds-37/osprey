# Remediation and verification

## Current support

| Capability | Status | Scope |
| --- | --- | --- |
| Deterministic local proposal | PARTIAL | CLI scans current evidence and can show a content-addressed proposal. |
| Safe target selection | PARTIAL | Uses only an advisory-provided fixed boundary and the shared version evaluator. An unknown target remains unknown. |
| Controlled apply | PARTIAL | CLI and API use the same explicit-approval applier; npm `package.json` plus `package-lock.json` v2/v3 only, no package manager or project code is executed. |
| Backend API workflow | PARTIAL | Create/retrieve/approve/apply/status/verification routes persist workflow state in the existing SQLite document store. Owner and organization context are enforced. |
| Remediation evidence | REAL | Proposal, approval, apply, rollback, and verification events use the existing canonical evidence ledger and SQLite adapter; raw project files are not stored. |
| Post-change verification | PARTIAL | CLI and API run the existing offline workspace scanner and share the same deterministic comparison. Complete advisory coverage is required; otherwise result is `UNKNOWN`. |
| Other package managers | ROADMAP | No controlled apply support for yarn, pnpm, Python, Docker, or OS packages. |

## Workflow

Run `osprey remediate <finding-id> --path <workspace>` to generate a proposal. Proposal mode does not write project files. The proposal identity includes the finding, scoped affected-version evidence, and SHA-256 hashes of the relevant manifest and lockfile. The selected target must come from advisory fixed-version evidence, evaluate outside the known affected range, satisfy the supported npm constraint, and already have lockfile metadata available. No registry query or installation is performed.

Apply with `osprey remediate <finding-id> --path <workspace> --apply <proposal-id> --approve`. This is explicit approval for the two named npm metadata files. Osprey rescans, regenerates the proposal, rechecks both content hashes before replacement, and fails stale proposals closed. Only the dependency declaration, the lockfile root declaration, and that dependency's direct resolved lock entry are changed. Unsupported syntax, absent target metadata, symlinks, invalid paths, or malformed data fail closed. No install scripts, package-manager process, branch, commit, or PR is created.

The API uses `POST /api/v1/remediation/proposals`, `GET /api/v1/remediation/proposals/{id}`, `POST .../{id}/approve`, `POST .../{id}/apply`, and read-only status/verification routes. Workspace paths are relative to configured `WORKSPACE_ROOT`; absolute paths, traversal, and resolved symlink escapes are rejected. An apply failure attempts to restore exact original bytes and records whether the original hashes were verified. Proposal files are not saved into the project.

## Verification and limits

After an apply, Osprey performs a fresh offline scan. The scanner records OSV cache coverage separately from findings. An empty legacy cache entry has unknown coverage; it cannot establish absence. A verified empty result is recorded as complete coverage. Verification is `FAILED` when a matching vulnerable finding remains, `VERIFIED` only when the expected lockfile state, complete advisory coverage, and retained affected-range evaluation all support resolution, and otherwise `UNKNOWN`. Runtime-loaded/exercised state remains independent and is never inferred from the dependency edit. Risk-before is taken from the finding; risk-after is taken from the post-scan finding when one remains, otherwise it is explicitly `UNKNOWN`, and delta is `UNKNOWN` when either score is absent.

The npm lock metadata supports a local resolved-dependency comparison; it does not prove installation, deployment, runtime load/execution, exploitability, production exposure, or absence of vulnerabilities outside the advisory coverage and analyzed scope. SHA-256 is an integrity check, not authenticity, immutable storage, or forensic chain of custody. Legacy `/tasks` routes remain deprecated compatibility endpoints and are not the authoritative proposal/apply workflow.
