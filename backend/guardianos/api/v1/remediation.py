"""Remediation & Human Approval API endpoints."""

from typing import List, Optional
from fastapi import Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import (
    CurrentUser,
    UserRole,
    get_current_user,
    require_role,
    require_single_organization,
)
from guardianos.remediation.models import RemediationTask
from guardianos.remediation.service import remediation_service
from guardianos.remediation.workflow import WorkflowError, remediation_workflow

router = SecuredAPIRouter(prefix="/remediation", tags=["Remediation"])


class ProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str = Field(min_length=1, max_length=512)
    workspace: str = Field(default=".", min_length=1, max_length=1024,
                            description="Workspace path relative to configured WORKSPACE_ROOT")


class ApplyProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace: str = Field(default=".", min_length=1, max_length=1024,
                            description="Workspace path relative to configured WORKSPACE_ROOT")


def _workflow_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except WorkflowError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc


@router.post("/proposals", status_code=status.HTTP_201_CREATED)
async def create_remediation_proposal(
    payload: ProposalRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.SECURITY_ENGINEER)),
):
    """Create and persist a read-only proposal from a fresh workspace scan."""
    return _workflow_call(remediation_workflow.create, payload.finding_id, payload.workspace,
                          user=current_user)


@router.get("/proposals/{proposal_id}")
async def get_remediation_proposal(
    proposal_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Retrieve a proposal only for its owner or an administrator in the same organization."""
    return _workflow_call(remediation_workflow.get, proposal_id, user=current_user)


@router.post("/proposals/{proposal_id}/approve")
async def approve_proposal_workflow(
    proposal_id: str,
    current_user: CurrentUser = Depends(require_role(UserRole.ADMIN)),
):
    """Record explicit administrator approval; this endpoint does not modify files."""
    return _workflow_call(remediation_workflow.approve, proposal_id, user=current_user)


@router.post("/proposals/{proposal_id}/apply")
async def apply_remediation_proposal(
    proposal_id: str,
    payload: ApplyProposalRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ADMIN)),
):
    """Apply an approved proposal and perform its post-apply scan and verification."""
    return _workflow_call(remediation_workflow.apply, proposal_id, payload.workspace,
                          user=current_user)


@router.get("/proposals/{proposal_id}/status")
async def get_remediation_status(
    proposal_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    return _workflow_call(remediation_workflow.status, proposal_id, user=current_user)


@router.get("/proposals/{proposal_id}/verification")
async def get_remediation_verification(
    proposal_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    return _workflow_call(remediation_workflow.verification, proposal_id, user=current_user)


@router.get("/tasks", response_model=List[RemediationTask], deprecated=True,
            dependencies=[Depends(require_single_organization)])
async def list_remediation_tasks(
    status: Optional[str] = Query(None, description="Filter by recommendation status; fixture records are explicitly flagged")
):
    """Legacy inventory recommendation records; use /proposals for the authoritative workflow."""
    return remediation_service.list_tasks(status=status)


@router.post("/tasks/{task_id}/approve", response_model=RemediationTask, deprecated=True,
             dependencies=[Depends(require_single_organization)])
async def approve_remediation_task(
    task_id: str,
    current_user: CurrentUser = Depends(require_role(UserRole.ADMIN)),
):
    """Admin-only approval of a remediation recommendation, attributed to the token identity."""
    try:
        task = remediation_service.approve_task(task_id=task_id, actor=current_user.username)
        return task
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/tasks/{task_id}/verify", response_model=RemediationTask, deprecated=True,
             dependencies=[Depends(require_single_organization)])
async def verify_remediation_task(task_id: str):
    """Compare current inventory evidence with the proposal; this cannot prove deployment or path closure."""
    try:
        task = remediation_service.verify_task(task_id=task_id)
        return task
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/generate", response_model=List[RemediationTask], status_code=status.HTTP_200_OK,
             deprecated=True, dependencies=[Depends(require_single_organization)])
async def generate_tasks():
    """Generate remediation tasks across all current findings and attack paths."""
    return remediation_service.generate_all_tasks()
