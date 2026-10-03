"""Remediation & Human Approval API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from guardianos.remediation.models import RemediationTask
from guardianos.remediation.service import remediation_service

router = APIRouter(prefix="/remediation", tags=["Remediation"])


class ApproveTaskRequest(BaseModel):
    actor: str = Field("security-lead", description="Name/email of approving human engineer")


@router.get("/tasks", response_model=List[RemediationTask])
async def list_remediation_tasks(
    status: Optional[str] = Query(None, description="Filter by status (PENDING_APPROVAL, APPROVED, VERIFIED_CLOSED)")
):
    """List actionable remediation tasks and generated Pull Request proposals."""
    return remediation_service.list_tasks(status=status)


@router.post("/tasks/{task_id}/approve", response_model=RemediationTask)
async def approve_remediation_task(task_id: str, payload: ApproveTaskRequest):
    """Human-in-the-loop approval gate for non-destructive PR deployment."""
    try:
        task = remediation_service.approve_task(task_id=task_id, actor=payload.actor)
        return task
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/tasks/{task_id}/verify", response_model=RemediationTask)
async def verify_remediation_task(task_id: str):
    """Trigger post-deployment verification rescan to confirm vulnerability resolution and attack path closure."""
    try:
        task = remediation_service.verify_task(task_id=task_id)
        return task
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/generate", response_model=List[RemediationTask], status_code=status.HTTP_200_OK)
async def generate_tasks():
    """Generate remediation tasks across all current findings and attack paths."""
    return remediation_service.generate_all_tasks()
