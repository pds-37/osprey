"""Vulnerability intelligence data models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field
from guardianos.inventory.models import Ecosystem


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnerabilitySource(str, Enum):
    OSV = "OSV"
    NVD = "NVD"
    GITHUB = "GHSA"
    DEBIAN = "Debian"
    VENDOR = "Vendor"


class VulnerabilityRecord(BaseModel):
    id: str = Field(..., description="Vulnerability ID (CVE-XXXX-XXXX, GHSA-XXXX, etc.)")
    aliases: List[str] = Field(default_factory=list)
    summary: str = Field(..., description="Short advisory summary")
    details: str = Field("", description="Detailed description and technical analysis")
    ecosystem: Ecosystem = Field(..., description="Affected package ecosystem")
    component_name: str = Field(..., description="Target package name")
    affected_version_ranges: List[str] = Field(default_factory=list, description="e.g. ['< 1.19.8', '>= 1.0.0']")
    fixed_versions: List[str] = Field(default_factory=list, description="Fixed release versions")
    severity: VulnerabilitySeverity = Field(default=VulnerabilitySeverity.UNKNOWN)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cwe_ids: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    modified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: VulnerabilitySource = Field(default=VulnerabilitySource.OSV)


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    vulnerability_id: str = Field(..., description="CVE or GHSA ID")
    component_purl: str = Field(..., description="PURL of the affected component")
    component_name: str = Field(...)
    installed_version: str = Field(...)
    fixed_version: Optional[str] = None
    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN
    is_fix_available: bool = False
    application: str = "default-app"
    environment: str = "production"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vulnerability: Optional[VulnerabilityRecord] = None
