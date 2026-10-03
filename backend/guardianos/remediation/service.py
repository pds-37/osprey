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

_remediation_tasks_db: Dict[str, RemediationTask] = {}


class RemediationService:
    """Coordinates remediation generation, human approval gates, and deployment verification."""

    def generate_all_tasks(self) -> List[RemediationTask]:
        findings = intel_service.list_findings()
        attack_paths = attack_path_service.list_paths()
        tasks = []

        for f in findings:
            comp = inventory_service.get_component(f.component_purl)
            if not comp:
                continue

            path = next((p for p in attack_paths if comp.name in p.name or f.component_purl == p.vulnerable_component), None)
            task = generate_remediation_task(finding=f, component=comp, attack_path=path)
            _remediation_tasks_db[task.id] = task
            tasks.append(task)

        return tasks

    def list_tasks(self, status: Optional[str] = None) -> List[RemediationTask]:
        tasks = list(_remediation_tasks_db.values())
        if not tasks:
            tasks = self.generate_all_tasks()
        if status:
            tasks = [t for t in tasks if t.status.value.lower() == status.lower()]
        return tasks

    def get_task(self, task_id: str) -> Optional[RemediationTask]:
        return _remediation_tasks_db.get(task_id)

    def approve_task(self, task_id: str, actor: str = "security-lead") -> RemediationTask:
        """Human approval action gate."""
        task = _remediation_tasks_db.get(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        task.status = RemediationStatus.APPROVED
        task.approval_actor = actor
        task.approved_at = datetime.now(timezone.utc)

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

    def verify_task(self, task_id: str) -> RemediationTask:
        """Trigger post-deployment verification."""
        task = _remediation_tasks_db.get(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        verify_remediation_closure(task)
        return task

    def clear(self) -> None:
        _remediation_tasks_db.clear()


remediation_service = RemediationService()
