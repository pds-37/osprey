"""SQLite-backed API orchestration for the shared Osprey remediation engine."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PureWindowsPath
from typing import Any

from osprey import __version__ as analyzer_version
from osprey.core.evidence import canonical_json
from osprey.core.models import EvidenceType
from osprey.remediation import (
    RemediationApplyError,
    RemediationProposal,
    apply_npm_proposal,
    create_proposal,
    verify_post_scan,
)
from osprey.scanner import ScanResult, scan_workspace

from guardianos.core.config import settings
from guardianos.core.security import single_organization_context_allowed
from guardianos.storage.evidence import evidence_store
from guardianos.storage.sqlite import state_store


RECORD_TYPE = "remediation_workflows"
MAX_WORKFLOW_RECORDS = 1000


class WorkflowError(Exception):
    def __init__(self, status_code: int, code: str):
        self.status_code = status_code
        self.code = code
        super().__init__(code)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _proposal_from_dict(raw: dict[str, Any]) -> RemediationProposal:
    data = dict(raw)
    for field in ("files_to_change", "limitations", "evidence_ids", "affected_records"):
        if field in data:
            data[field] = tuple(data[field])
    return RemediationProposal(**data)


class RemediationWorkflow:
    """Coordinates approval, the shared safe applier, post-scan, and evidence."""

    def _allowed_root(self) -> Path:
        raw = settings.WORKSPACE_ROOT or str(Path.cwd())
        try:
            return Path(raw).expanduser().resolve(strict=True)
        except OSError as exc:
            raise WorkflowError(500, "WORKSPACE_ROOT_UNAVAILABLE") from exc

    def resolve_workspace(self, relative_path: str | None) -> tuple[Path, str]:
        if relative_path is None:
            relative_path = "."
        if (not isinstance(relative_path, str) or not relative_path or len(relative_path) > 1024
                or any(ord(char) < 32 for char in relative_path)):
            raise WorkflowError(422, "INVALID_WORKSPACE_PATH")
        candidate_syntax = Path(relative_path)
        windows_syntax = PureWindowsPath(relative_path)
        if candidate_syntax.is_absolute() or windows_syntax.is_absolute() or windows_syntax.drive:
            raise WorkflowError(403, "ABSOLUTE_WORKSPACE_PATH_FORBIDDEN")
        if ".." in candidate_syntax.parts or ".." in windows_syntax.parts:
            raise WorkflowError(403, "WORKSPACE_PATH_TRAVERSAL")
        root = self._allowed_root()
        requested = root / candidate_syntax
        try:
            resolved = requested.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise WorkflowError(403, "WORKSPACE_OUTSIDE_ALLOWED_ROOT") from exc
        if not resolved.is_dir():
            raise WorkflowError(422, "WORKSPACE_NOT_DIRECTORY")
        # The stored identity is opaque and does not disclose the local path.
        workspace_key = hashlib.sha256(str(resolved).casefold().encode("utf-8")).hexdigest()
        return resolved, workspace_key

    @staticmethod
    def _scan(root: Path) -> ScanResult:
        # Use the existing Osprey scanner and its offline advisory cache.
        return scan_workspace(root, offline=True)

    @staticmethod
    def _finding(scan: ScanResult, finding_id: str):
        return next((item for item in scan.findings if item.id == finding_id), None)

    def _record_event(
        self,
        workflow: dict[str, Any],
        event_type: EvidenceType,
        name: str,
        observed: dict[str, Any],
    ) -> str:
        proposal = workflow.get("proposal") if isinstance(workflow.get("proposal"), dict) else {}
        application = workflow.get("application") if isinstance(workflow.get("application"), dict) else {}
        verification = workflow.get("verification") if isinstance(workflow.get("verification"), dict) else {}
        after_state: dict[str, Any] = {"state": "UNKNOWN"}
        if application.get("status") == "APPLIED":
            after_state = {
                "state": "APPLIED",
                "version": application.get("target_version", proposal.get("target_version")),
                "file_hashes": application.get("modified_hashes", {}),
            }
        elif application:
            after_state = {
                "state": application.get("status", "UNKNOWN"),
                "rollback_verified": application.get("rollback_verified"),
            }
        if verification:
            after_state = {
                "state": verification.get("state", "UNKNOWN"),
                "locked_versions": verification.get("observed_locked_versions", []),
                "matching_findings": verification.get("matching_findings", []),
            }
        input_hashes = proposal.get("input_hashes", {})
        modified_hashes = application.get("modified_hashes", {})
        payload = {
            "dependency_identity": {
                "package": proposal.get("package"),
                "package_manager": proposal.get("package_manager"),
            },
            "before_state": {
                "version": proposal.get("current_version"),
                "file_hashes": input_hashes,
            },
            "proposed_state": {
                "version": proposal.get("target_version"),
                "status": proposal.get("status", "UNKNOWN"),
            },
            "after_state": after_state,
            "file_hashes": {"before": input_hashes, "after": modified_hashes},
            "package_manager": proposal.get("package_manager"),
            "verification_state": workflow.get("verification_state", "UNKNOWN"),
            "evidence_references": list(dict.fromkeys([
                *workflow.get("finding_evidence_ids", []),
                *workflow.get("evidence_ids", []),
            ])),
            **observed,
            "proposal_id": workflow["proposal_id"],
            "finding_id": workflow["finding_id"],
            "analyzer": "Osprey",
            "analyzer_version": analyzer_version,
            "observed_at": _now(),
        }
        record = evidence_store.add(
            evidence_type=event_type,
            source="Osprey remediation workflow",
            location=f"remediation:{workflow['proposal_id']}:{name}",
            content=canonical_json(payload),
            metadata={
                "analyzer": "Osprey",
                "analyzer_version": analyzer_version,
                "analysis_type": name,
                "proposal_id": workflow["proposal_id"],
                "finding_id": workflow["finding_id"],
                "observed": payload,
            },
        )
        workflow.setdefault("evidence_ids", []).append(record.id)
        workflow["evidence_ids"] = list(dict.fromkeys(workflow["evidence_ids"]))
        return record.id

    def _save(self, workflow: dict[str, Any]) -> None:
        state_store.put(RECORD_TYPE, workflow["proposal_id"], workflow)

    @staticmethod
    def _persist_finding_evidence(scan: ScanResult, finding: Any) -> tuple[list[str], list[str]]:
        available = {item.id: item for item in scan.evidence}
        persisted: list[str] = []
        missing: list[str] = []
        for evidence_id in finding.evidence_ids:
            record = available.get(evidence_id)
            if record is None:
                if evidence_store.get(evidence_id) is not None:
                    persisted.append(evidence_id)
                else:
                    missing.append(evidence_id)
                continue
            stored = evidence_store.add(
                evidence_type=record.type,
                source=record.source,
                location=record.location,
                content_hash=record.content_hash,
                confidence=record.confidence,
                metadata=record.metadata,
            )
            persisted.append(stored.id)
        return list(dict.fromkeys(persisted)), list(dict.fromkeys(missing))

    @staticmethod
    def _load(proposal_id: str) -> dict[str, Any]:
        if not isinstance(proposal_id, str) or len(proposal_id) != 27 or not proposal_id.startswith("rp-"):
            raise WorkflowError(404, "PROPOSAL_NOT_FOUND")
        item = state_store.get(RECORD_TYPE, proposal_id)
        if item is None or item.get("proposal_id") != proposal_id:
            raise WorkflowError(404, "PROPOSAL_NOT_FOUND")
        return item

    @staticmethod
    def _authorize_record(workflow: dict[str, Any], *, username: str, org_id: str, role: str) -> None:
        if workflow.get("org_id") != org_id:
            raise WorkflowError(404, "PROPOSAL_NOT_FOUND")
        if workflow.get("owner") != username and role != "admin":
            raise WorkflowError(404, "PROPOSAL_NOT_FOUND")

    def create(self, finding_id: str, workspace: str | None, *, user: Any) -> dict[str, Any]:
        if not single_organization_context_allowed(user.org_id):
            raise WorkflowError(409, "WORKSPACE_ACCESS_REQUIRES_SINGLE_ORGANIZATION_MODE")
        root, workspace_key = self.resolve_workspace(workspace)
        scan = self._scan(root)
        finding = self._finding(scan, finding_id)
        if finding is None:
            raise WorkflowError(404, "FINDING_NOT_FOUND_IN_WORKSPACE")
        proposal = create_proposal(root, finding)
        persisted_finding_evidence, missing_finding_evidence = self._persist_finding_evidence(scan, finding)
        existing = state_store.list(RECORD_TYPE)
        if len(existing) >= MAX_WORKFLOW_RECORDS and proposal.proposal_id not in existing:
            raise WorkflowError(507, "REMEDIATION_RECORD_LIMIT")
        prior = state_store.get(RECORD_TYPE, proposal.proposal_id)
        if prior is not None:
            self._authorize_record(prior, username=user.username, org_id=user.org_id, role=user.role.value)
            # Re-creation is idempotent only while the same canonical proposal remains current.
            if canonical_json(prior.get("proposal")) != canonical_json(asdict(proposal)):
                raise WorkflowError(409, "STALE_PROPOSAL")
            return prior
        state = {
            "proposal_id": proposal.proposal_id,
            "finding_id": finding.id,
            "owner": user.username,
            "org_id": user.org_id,
            "workspace_key": workspace_key,
            "status": proposal.status,
            "verification_state": "UNKNOWN",
            "proposal": asdict(proposal),
            "finding_evidence_ids": persisted_finding_evidence,
            "missing_finding_evidence_ids": missing_finding_evidence,
            "created_at": _now(),
            "updated_at": _now(),
            "evidence_ids": [],
            "approval": None,
            "application": None,
            "verification": None,
        }
        self._record_event(state, EvidenceType.REMEDIATION_PROPOSAL, "proposal", {
            "dependency": proposal.package,
            "current_version": proposal.current_version,
            "target_version": proposal.target_version,
            "package_manager": proposal.package_manager,
            "files": list(proposal.files_to_change),
            "input_hashes": proposal.input_hashes,
            "finding_evidence_ids": persisted_finding_evidence,
            "limitations": list(proposal.limitations),
        })
        self._save(state)
        return state

    def get(self, proposal_id: str, *, user: Any) -> dict[str, Any]:
        state = self._load(proposal_id)
        self._authorize_record(state, username=user.username, org_id=user.org_id, role=user.role.value)
        return state

    def approve(self, proposal_id: str, *, user: Any) -> dict[str, Any]:
        state = self._load(proposal_id)
        self._authorize_record(state, username=user.username, org_id=user.org_id, role=user.role.value)
        if state.get("status") != "PROPOSED":
            raise WorkflowError(409, "PROPOSAL_NOT_APPROVABLE")
        state["approval"] = {"actor": user.username, "approved_at": _now(), "explicit": True}
        state["status"] = "APPROVED"
        state["updated_at"] = _now()
        self._record_event(state, EvidenceType.REMEDIATION_APPROVAL, "approval", {
            "actor": user.username, "status": "APPROVED",
            "input_hashes": state["proposal"]["input_hashes"],
        })
        self._save(state)
        return state

    def verification(self, proposal_id: str, *, user: Any) -> dict[str, Any]:
        state = self.get(proposal_id, user=user)
        return {"proposal_id": proposal_id,
                "state": state.get("verification_state", "UNKNOWN"),
                "result": state.get("verification"),
                "evidence_ids": state.get("evidence_ids", [])}

    def status(self, proposal_id: str, *, user: Any) -> dict[str, Any]:
        state = self.get(proposal_id, user=user)
        return {"proposal_id": proposal_id,
                "status": state.get("status", "UNKNOWN"),
                "verification_state": state.get("verification_state", "UNKNOWN"),
                "updated_at": state.get("updated_at"),
                "evidence_ids": state.get("evidence_ids", [])}

    def apply(self, proposal_id: str, workspace: str | None, *, user: Any) -> dict[str, Any]:
        state = self._load(proposal_id)
        self._authorize_record(state, username=user.username, org_id=user.org_id, role=user.role.value)
        if not single_organization_context_allowed(user.org_id):
            raise WorkflowError(409, "WORKSPACE_ACCESS_REQUIRES_SINGLE_ORGANIZATION_MODE")
        if state.get("status") == "APPLYING":
            raise WorkflowError(409, "APPLY_IN_PROGRESS_OR_INTERRUPTED")
        if state.get("status") in {"APPLIED", "VERIFIED", "VERIFICATION_FAILED", "UNKNOWN", "FAILED", "STALE_PROPOSAL"}:
            raise WorkflowError(409, "DUPLICATE_OR_REPLAYED_APPLY")
        if state.get("status") != "APPROVED" or not state.get("approval", {}).get("explicit"):
            raise WorkflowError(409, "EXPLICIT_APPROVAL_REQUIRED")
        root, workspace_key = self.resolve_workspace(workspace)
        if workspace_key != state.get("workspace_key"):
            raise WorkflowError(403, "PROPOSAL_WORKSPACE_MISMATCH")
        proposal = _proposal_from_dict(state["proposal"])
        before_scan = self._scan(root)
        finding = self._finding(before_scan, state["finding_id"])
        if finding is None:
            state["status"] = "STALE_PROPOSAL"
            state["updated_at"] = _now()
            self._record_event(state, EvidenceType.REMEDIATION_APPLICATION, "stale_apply", {
                "status": "STALE_PROPOSAL", "reason": "Original finding is absent from the fresh pre-apply scan.",
                "limitations": ["No files were changed."],
            })
            self._save(state)
            raise WorkflowError(409, "STALE_PROPOSAL")
        claimed = state_store.update_if_field(
            RECORD_TYPE,
            proposal_id,
            {"status": "APPROVED", "approval": state.get("approval")},
            {"status": "APPLYING", "updated_at": _now()},
        )
        if claimed is None:
            raise WorkflowError(409, "DUPLICATE_OR_REPLAYED_APPLY")
        state = claimed
        self._record_event(state, EvidenceType.REMEDIATION_APPLICATION, "apply_attempt", {
            "status": "APPLYING", "files": proposal.files_to_change,
            "input_hashes": proposal.input_hashes,
        })
        self._save(state)
        try:
            result = apply_npm_proposal(root, proposal, approved=True, finding=finding)
        except RemediationApplyError as exc:
            state["status"] = "FAILED"
            state["application"] = {"status": "FAILED", "rollback_verified": exc.rollback_verified,
                                     "files_attempted": list(exc.files_attempted), "error": str(exc)}
            self._record_event(state, EvidenceType.REMEDIATION_ROLLBACK, "rollback", {
                **state["application"], "original_hashes": proposal.input_hashes,
                "modified_hashes": exc.modified_hashes,
                "limitations": ["Rollback is verified only for files whose original hashes match."],
            })
            self._save(state)
            raise WorkflowError(500, "APPLY_FAILED_ROLLBACK_VERIFIED" if exc.rollback_verified
                                else "APPLY_FAILED_ROLLBACK_FAILED") from exc
        except (RuntimeError, ValueError, OSError, PermissionError) as exc:
            state["status"] = "STALE_PROPOSAL" if "STALE_PROPOSAL" in str(exc) else "FAILED"
            state["application"] = {"status": state["status"], "error": type(exc).__name__,
                                     "rollback_verified": None,
                                     "limitations": ["No successful file change was reported by the applier."]}
            self._record_event(state, EvidenceType.REMEDIATION_APPLICATION, "apply_failed", state["application"])
            self._save(state)
            raise WorkflowError(409 if state["status"] == "STALE_PROPOSAL" else 500,
                                state["status"]) from exc
        state["application"] = result
        state["status"] = "APPLIED"
        state["updated_at"] = _now()
        self._record_event(state, EvidenceType.REMEDIATION_APPLICATION, "application", {
            **result, "before": {"version": proposal.current_version,
                                  "finding_id": proposal.finding_id},
            "after": {"version": proposal.target_version},
            "package_manager": proposal.package_manager,
            "limitations": result["limitations"],
        })
        self._save(state)
        try:
            after_scan = self._scan(root)
            verification = verify_post_scan(proposal, after_scan)
        except Exception as exc:
            verification = {
                "state": "UNKNOWN",
                "reason": "Post-remediation scan could not establish verification.",
                "error": type(exc).__name__,
                "risk_after": {"score": None, "level": "UNKNOWN", "decision": "UNKNOWN"},
                "risk_delta": None,
                "limitations": ["The post-remediation scan did not complete successfully."],
            }
        state["verification"] = verification
        state["verification_state"] = verification["state"]
        state["status"] = "VERIFIED" if verification["state"] == "VERIFIED" else (
            "VERIFICATION_FAILED" if verification["state"] == "FAILED" else "UNKNOWN")
        state["updated_at"] = _now()
        self._record_event(state, EvidenceType.REMEDIATION_VERIFICATION, "verification", verification)
        self._save(state)
        return state

remediation_workflow = RemediationWorkflow()
