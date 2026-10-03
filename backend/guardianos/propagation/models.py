"""Patch Propagation Tracker data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PropagationStage(str, Enum):
    UPSTREAM_FIX = "UPSTREAM_FIX"
    SECURITY_ADVISORY = "SECURITY_ADVISORY"
    DISTRIBUTION_PACKAGE = "DISTRIBUTION_PACKAGE"
    BASE_IMAGE_REBUILD = "BASE_IMAGE_REBUILD"
    APPLICATION_IMAGE_REBUILD = "APPLICATION_IMAGE_REBUILD"
    PRODUCTION_DEPLOYMENT = "PRODUCTION_DEPLOYMENT"


class StageStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StageDetail(BaseModel):
    stage: PropagationStage
    status: StageStatus
    evidence: str
    version_or_tag: Optional[str] = None
    completed_at: Optional[datetime] = None


class PatchPropagationRecord(BaseModel):
    id: str = Field(..., description="Unique propagation tracking ID")
    component_name: str
    installed_purl: str
    installed_version: str
    vulnerability_id: str
    fixed_version: str
    application: str
    environment: str
    stages: Dict[PropagationStage, StageDetail]
    bottleneck_stage: PropagationStage
    is_production_exposed: bool
    summary_explanation: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
