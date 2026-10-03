"""Upstream change monitoring data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ChangeClassification(str, Enum):
    UNKNOWN = "UNKNOWN"
    SUSPECTED_SECURITY_CHANGE = "SUSPECTED_SECURITY_CHANGE"
    CORROBORATED = "CORROBORATED"
    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class CommitRecord(BaseModel):
    id: str = Field(..., description="Commit SHA or unique reference")
    commit_sha: str = Field(...)
    repository: str = Field(..., description="e.g. strukturag/libheif or ImageMagick/ImageMagick")
    component_name: str = Field(..., description="Target component name")
    author: str = Field(...)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = Field(..., description="Commit message header and description")
    diff_summary: Optional[str] = Field(None, description="Summary or snippet of diff changes")
    files_changed: List[str] = Field(default_factory=list)
    classification: ChangeClassification = Field(default=ChangeClassification.UNKNOWN)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detected_signals: List[str] = Field(default_factory=list)
    reasoning: str = Field("")
    potential_fixed_version: Optional[str] = None
