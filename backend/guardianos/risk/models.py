"""Contextual Risk Engine data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskFactor(BaseModel):
    name: str
    weight: float
    score: Optional[float] = Field(None, ge=0.0, le=100.0)
    description: str


class ContextualRiskScore(BaseModel):
    id: str = Field(..., description="Unique risk finding ID")
    finding_id: str
    component_purl: str
    component_name: str
    vulnerability_id: str
    risk_level: RiskLevel
    decision: str = "UNKNOWN"
    composite_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    evidence_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    fixture: bool = False
    cvss_score: Optional[float] = None
    reasons: List[str] = Field(default_factory=list)
    factors: List[RiskFactor] = Field(default_factory=list)
    risk_inputs: dict[str, Any] = Field(default_factory=dict)
    attack_path_id: Optional[str] = None
    potential_impact: str = ""
    evidence: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    provenance_ids: dict[str, str] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
