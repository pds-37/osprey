"""Attack Path Engine data models."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeRole(str, Enum):
    ENTRY_POINT = "ENTRY_POINT"
    ROUTE = "ROUTE"
    SERVICE = "SERVICE"
    VULNERABLE_COMPONENT = "VULNERABLE_COMPONENT"
    EXECUTION_PRIMITIVE = "EXECUTION_PRIMITIVE"
    PRIVILEGE_TRANSITION = "PRIVILEGE_TRANSITION"
    HIGH_VALUE_TARGET = "HIGH_VALUE_TARGET"


class AttackPathNode(BaseModel):
    id: str = Field(..., description="Unique graph node ID")
    label: str = Field(..., description="Human-readable label (e.g., 'Internet', 'POST /upload', 'libheif')")
    role: NodeRole
    description: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)


class AttackPathStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class AttackPath(BaseModel):
    id: str = Field(..., description="Unique attack path identifier")
    name: str = Field(..., description="e.g. Unauthenticated RCE to Cloud S3 Storage via libheif")
    entry_point: str = Field(..., description="Entry point node or route")
    vulnerable_component: str = Field(..., description="PURL of affected component")
    vulnerability_id: str = Field(..., description="CVE or GHSA identifier")
    target_resource: str = Field(..., description="High-value destination asset")
    nodes: List[AttackPathNode] = Field(default_factory=list)
    step_edges: List[Dict[str, str]] = Field(default_factory=list)
    exploitation_condition: str = Field("", description="Preconditions required for exploitation")
    privilege_transitions: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    status: AttackPathStatus = Field(default=AttackPathStatus.OPEN)
    recommended_remediation: str = Field("")
