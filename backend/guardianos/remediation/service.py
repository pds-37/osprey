"""Remediation Service managing approval workflows and verification rescans."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from guardianos.attackpath.service import attack_path_service
from guardianos.core.audit import record_audit_event
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.remediation.generator import generate_remediation_task
from guardianos.remediation.models import RemediationStatus, RemediationTask
from guardianos.remediation.verifier import verify_remediation_closure
from guardianos.storage.sqlite import state_store

_remediation_tasks_db: Dict[str, RemediationTask] = {
    key: RemediationTask.model_validate(value)
    for key, value in state_store.list("remediation_tasks").items()
}


class RemediationService:
    """Coordinates remediation generation, human approval gates, and deployment verification."""

    def generate_all_tasks(self) -> List[RemediationTask]:
        findings = intel_service.list_findings()
        attack_paths = attack_path_service.list_paths()
        tasks = []
        if not findings:
            return []

        for f in findings:
            comp = inventory_service.get_component(f.component_purl)
            if not comp:
                continue

            path = next((p for p in attack_paths if comp.name in p.name or f.component_purl == p.vulnerable_component), None)
            task = generate_remediation_task(finding=f, component=comp, attack_path=path)
            previous = _remediation_tasks_db.get(task.id)
            if previous:
                task.status = previous.status
                task.approval_actor = previous.approval_actor
                task.approved_at = previous.approved_at
                task.verified_at = previous.verified_at
                task.verification_evidence = previous.verification_evidence
                task.created_at = previous.created_at
            _remediation_tasks_db[task.id] = task
            state_store.put("remediation_tasks", task.id, task)
            tasks.append(task)

        return tasks

    def list_tasks(self, status: Optional[str] = None) -> List[RemediationTask]:
        tasks = list(_remediation_tasks_db.values())
        if status:
            tasks = [t for t in tasks if t.status.value.lower() == status.lower()]
        return tasks

    def _find_task(self, task_id: str) -> Optional[RemediationTask]:
        task = _remediation_tasks_db.get(task_id)
        if task is not None:
            return task
        # Regeneration is allowed to refresh proposals, but identifiers must match
        # exactly; component-name substring matches are ambiguous.
        if not _remediation_tasks_db:
            self.generate_all_tasks()
        return _remediation_tasks_db.get(task_id)

    def get_task(self, task_id: str) -> Optional[RemediationTask]:
        return self._find_task(task_id)

    def approve_task(self, task_id: str, actor: str) -> RemediationTask:
        """Human approval action gate."""
        task = self._find_task(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        task.status = RemediationStatus.APPROVED
        task.approval_actor = actor
        task.approved_at = datetime.now(timezone.utc)
        state_store.put("remediation_tasks", task.id, task)

        record_audit_event(
            action="REMEDIATION_APPROVED",
            target_type="RemediationTask",
            target_id=task.id,
            actor=actor,
            details={
                "component": task.component_name,
                "from_version": task.current_version,
                "to_version": task.target_version,
                "branch": task.pull_request.branch_name
            }
        )
        return task

    def verify_task(self, task_id: str, *, include_demo_fixtures: bool = False) -> RemediationTask:
        """Trigger post-deployment verification."""
        task = self._find_task(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        verify_remediation_closure(task, include_demo_fixtures=include_demo_fixtures)
        state_store.put("remediation_tasks", task.id, task)
        return task

    def clear(self) -> None:
        _remediation_tasks_db.clear()
        state_store.clear("remediation_tasks")


remediation_service = RemediationService()
