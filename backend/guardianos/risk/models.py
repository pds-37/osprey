"""Contextual Risk Engine data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskFactor(BaseModel):
    name: str
    weight: float
    score: float
    description: str


class ContextualRiskScore(BaseModel):
    id: str = Field(..., description="Unique risk finding ID")
    finding_id: str
    component_purl: str
    component_name: str
    vulnerability_id: str
    risk_level: RiskLevel
    composite_score: float = Field(..., ge=0.0, le=100.0)
    cvss_score: Optional[float] = None
    reasons: List[str] = Field(default_factory=list)
    factors: List[RiskFactor] = Field(default_factory=list)
    attack_path_id: Optional[str] = None
    potential_impact: str = ""
    evidence: List[str] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
