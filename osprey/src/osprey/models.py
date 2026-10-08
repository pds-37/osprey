"""Data models representing software components, services, exposure, and vulnerability findings.

Assumptions and Limitations:
- Exposure observations and function reachability are separate evidence layers. The
  reachability analyzer is a conservative static subset, not a complete call graph.
- Component versions are parsed from lockfiles and manifests as text without execution.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from osprey.core.models import Evidence, ReachabilityResult, ReachabilityStatus, VersionMatchStatus


@dataclass
class ExposureInfo:
    """Network and operational exposure context for a component or service."""

    level: str  # 'public', 'internal', 'dev-only', 'unknown'
    confidence: str  # 'declared', 'inferred', 'unknown'
    evidence: str  # e.g. "Dockerfile: EXPOSE 8080" or "package.json devDependencies"

    def to_display(self) -> str:
        """Format a human-readable summary of exposure."""
        if self.confidence == "inferred":
            return f"{self.level} (inferred: {self.evidence})"
        if self.confidence == "declared":
            return f"{self.level} (declared override: {self.evidence})"
        return self.level


@dataclass
class Component:
    """A software library, package, or container dependency."""

    name: str
    version: str
    ecosystem: str  # 'npm', 'PyPI', 'Debian', 'Go', 'crates.io', etc.
    purl: str
    is_dev: bool = False
    source_file: str = ""
    license: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    declared_version: Optional[str] = None
    locked_version: Optional[str] = None
    installed_version: Optional[str] = None
    installation_evidence_id: Optional[str] = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem.lower()}:{self.name.lower()}@{self.version}"

    @property
    def observation_id(self) -> str:
        source = self.source_file.replace("\\", "/")
        identity = f"{self.key}|{source}|{'dev' if self.is_dev else 'prod'}"
        return "obs-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


@dataclass
class Service:
    """An application, container, or daemon grouping components together."""

    name: str
    source_file: str = ""
    ports: List[int] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    exposure: Optional[ExposureInfo] = None
    build_context: Optional[str] = None
    dockerfile_path: Optional[str] = None
    copied_files: List[str] = field(default_factory=list)

    @property
    def ports_declared(self) -> bool:
        """Whether a source manifest declares ports; this does not prove public ingress."""
        return bool(self.ports)



@dataclass
class FixStatus:
    """Availability of security patches across the software supply chain lifecycle.

    v0.1 Scope:
    Stage 1 ('upstream fix released') is derived directly from upstream vulnerability feeds.
    Stages 2-5 are roadmap stages displayed transparently to developers.
    """

    status: str = "upstream fix released"  # 'upstream fix released', 'no fix available', 'unknown'
    fixed_version: Optional[str] = None
    minimal_safe_version: Optional[str] = None  # e.g. ">= 1.19.8"
    stages: Dict[str, str] = field(default_factory=lambda: {
        "stage_1_upstream": "upstream fix released",
        "stage_2_distro": "not tracked yet (roadmap)",
        "stage_3_base_image": "not tracked yet (roadmap)",
        "stage_4_lockfile": "not tracked yet (roadmap)",
        "stage_5_production": "not tracked yet (roadmap)",
    })


@dataclass
class Finding:
    """Correlated security vulnerability finding with contextual risk and exposure."""

    id: str
    vulnerability_id: str
    component: Component
    exposure: ExposureInfo
    fix_status: FixStatus
    risk_tier: str  # 'ACT NOW', 'PLAN', 'MONITOR', 'IGNORE', or 'UNKNOWN'
    firing_rule: str
    service: Optional[Service] = None
    cvss_score: Optional[float] = None
    severity: str = "UNKNOWN"
    epss_score: Optional[float] = None
    in_cisa_kev: bool = False
    kev_available: bool = False
    risk_score: Optional[float] = None
    risk_level: str = "UNKNOWN"
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    risk_limitations: List[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    aliases: List[str] = field(default_factory=list)
    raw_vuln: Dict[str, Any] = field(default_factory=dict)
    package_status: VersionMatchStatus = VersionMatchStatus.UNKNOWN
    reachability: ReachabilityResult = field(
        default_factory=lambda: ReachabilityResult(
            status=ReachabilityStatus.UNKNOWN,
            confidence=0.0,
            reason="Function-level reachability has not been analyzed.",
        )
    )
    evidence_ids: List[str] = field(default_factory=list)
    risk_inputs: Dict[str, Any] = field(default_factory=dict)
    provenance_ids: Dict[str, str] = field(default_factory=dict)
    runtime_state: Dict[str, str] = field(default_factory=lambda: {
        "DECLARED": "UNKNOWN",
        "LOCKED": "UNKNOWN",
        "INSTALLED": "UNKNOWN",
        "LOADED": "UNKNOWN",
        "EXERCISED": "UNKNOWN",
    })
    runtime_evidence_ids: List[str] = field(default_factory=list)
    runtime_limitations: List[str] = field(default_factory=lambda: [
        "No linked runtime instrumentation evidence; LOADED and EXERCISED remain UNKNOWN.",
    ])
