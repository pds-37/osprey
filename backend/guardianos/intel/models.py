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
    UNKNOWN = "UNKNOWN"
    DEMO_FIXTURE = "DEMO_FIXTURE"
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
    affected_ranges: List[dict[str, Any]] = Field(default_factory=list, description="Normalized OSV range records")
    affected_versions: List[str] = Field(default_factory=list, description="Exact affected versions when provided")
    introduced_versions: List[str] = Field(default_factory=list, description="Explicit introduction boundaries")
    vulnerable_symbols: List[str] = Field(default_factory=list, description="Advisory-supported vulnerable symbols")
    vulnerable_symbol_mappings: List[dict[str, Any]] = Field(
        default_factory=list,
        description="Package-scoped advisory symbol mappings with source and mapping confidence",
    )
    query_matched_version: Optional[str] = Field(None, description="Version included in a successful OSV query")
    fixed_versions: List[str] = Field(default_factory=list, description="Fixed release versions")
    severity: VulnerabilitySeverity = Field(default=VulnerabilitySeverity.UNKNOWN)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cwe_ids: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    source_content_hash: Optional[str] = Field(None, pattern=r"^[0-9a-fA-F]{64}$")
    source: VulnerabilitySource = Field(default=VulnerabilitySource.UNKNOWN)


class VulnerabilityFinding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    vulnerability_id: str = Field(..., description="CVE or GHSA ID")
    component_purl: str = Field(..., description="PURL of the affected component")
    component_name: str = Field(...)
    observed_version: str = Field("", description="Version used for advisory matching; not necessarily installed")
    installed_version: Optional[str] = Field(None, description="Version proved by installed metadata, when available")
    declared_version: Optional[str] = None
    locked_version: Optional[str] = None
    fixed_version: Optional[str] = None
    severity: VulnerabilitySeverity = VulnerabilitySeverity.UNKNOWN
    is_fix_available: bool = False
    package_status: str = "UNKNOWN"
    reachability_status: str = "UNKNOWN"
    reachability_confidence: float = Field(0.0, ge=0.0, le=1.0)
    reachability_path: List[str] = Field(default_factory=list)
    reachability_path_edges: List[dict[str, Any]] = Field(default_factory=list)
    reachability_explanation: str = "Reachability has not been analyzed."
    reachability_limitations: List[str] = Field(default_factory=list)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    kev_listed: Optional[bool] = None
    kev_available: bool = False
    runtime_state: dict[str, str] = Field(default_factory=lambda: {
        "DECLARED": "UNKNOWN",
        "LOCKED": "UNKNOWN",
        "INSTALLED": "UNKNOWN",
        "LOADED": "UNKNOWN",
        "EXERCISED": "UNKNOWN",
    })
    runtime_evidence_ids: List[str] = Field(default_factory=list)
    runtime_limitations: List[str] = Field(default_factory=lambda: [
        "No linked runtime instrumentation evidence; LOADED and EXERCISED remain UNKNOWN.",
    ])
    evidence_ids: List[str] = Field(default_factory=list)
    provenance_ids: dict[str, str] = Field(default_factory=dict)
    analysis_provenance_id: Optional[str] = None
    application: str = "default-app"
    environment: str = "unknown"
    organization_id: str = Field(default="default-org", max_length=128)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    vulnerability: Optional[VulnerabilityRecord] = None
