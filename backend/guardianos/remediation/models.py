"""Remediation & Verification Engine data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RemediationActionType(str, Enum):
    UPGRADE_PACKAGE = "UPGRADE_PACKAGE"
    UPGRADE_BASE_IMAGE = "UPGRADE_BASE_IMAGE"
    REBUILD_CONTAINER = "REBUILD_CONTAINER"
    RESTRICT_ENDPOINT = "RESTRICT_ENDPOINT"
    ISOLATE_WORKLOAD = "ISOLATE_WORKLOAD"


class RemediationStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEPLOYED = "DEPLOYED"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"
    UNVERIFIED = "UNVERIFIED"


class PullRequestProposal(BaseModel):
    title: str = Field(..., description="PR title following conventional commits")
    body: str = Field(..., description="Detailed description with CVE context and evidence")
    branch_name: Optional[str] = None
    target_file: Optional[str] = None
    diff_content: Optional[str] = Field(None, description="Populated only when a real repository diff is generated")


class RemediationTask(BaseModel):
    id: str = Field(..., description="Unique remediation task ID")
    vulnerability_id: str
    component_name: str
    current_version: str
    target_version: str
    action_type: RemediationActionType
    status: RemediationStatus = RemediationStatus.PENDING_APPROVAL
    pull_request: PullRequestProposal
    associated_attack_path_id: Optional[str] = None
    approval_actor: Optional[str] = None
    approved_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    verification_evidence: Optional[Dict[str, Any]] = None
    fixture: bool = Field(default=False, description="True only when this recommendation is associated with demo fixture data")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
