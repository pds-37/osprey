"""Canonical, adapter-neutral analysis models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceType(str, Enum):
    MANIFEST = "MANIFEST"
    LOCKFILE = "LOCKFILE"
    SBOM = "SBOM"
    SOURCE_FILE = "SOURCE_FILE"
    IMPORT = "IMPORT"
    ROUTE = "ROUTE"
    FUNCTION = "FUNCTION"
    SOURCE_EXPOSURE = "SOURCE_EXPOSURE"
    VERSION = "VERSION"
    VULNERABILITY_ADVISORY = "VULNERABILITY_ADVISORY"
    VULNERABLE_SYMBOL = "VULNERABLE_SYMBOL"
    REACHABILITY = "REACHABILITY"
    ANALYSIS_LIMITATION = "ANALYSIS_LIMITATION"
    ANALYSIS_RUN = "ANALYSIS_RUN"
    RISK = "RISK"
    INSTALLATION_OBSERVATION = "INSTALLATION_OBSERVATION"
    EPSS = "EPSS"
    CISA_KEV = "CISA_KEV"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    USER_INPUT = "USER_INPUT"
    REMEDIATION_PROPOSAL = "REMEDIATION_PROPOSAL"
    REMEDIATION_APPROVAL = "REMEDIATION_APPROVAL"
    REMEDIATION_APPLICATION = "REMEDIATION_APPLICATION"
    REMEDIATION_ROLLBACK = "REMEDIATION_ROLLBACK"
    REMEDIATION_VERIFICATION = "REMEDIATION_VERIFICATION"


class ReachabilityStatus(str, Enum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNKNOWN = "UNKNOWN"


class VersionMatchStatus(str, Enum):
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class RuntimeObservationState(str, Enum):
    """Positive runtime facts recorded only when an instrumentation event occurs."""

    LOADED = "LOADED"
    EXERCISED = "EXERCISED"


@dataclass(frozen=True)
class Evidence:
    id: str
    type: EvidenceType
    source: str
    location: str
    timestamp: str
    confidence: float
    content_hash: str
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    # Additive for compatibility with records written before envelope verification.
    record_hash: str = ""


@dataclass(frozen=True)
class ReachabilityEdge:
    """One observed edge in a bounded source-level reachability path."""

    source_file: str
    source_symbol: str
    target_file: str | None
    target_symbol: str
    relation: str
    resolution: str
    confidence: float
    line: int | None = None
    evidence_id: str | None = None


@dataclass(frozen=True)
class ComponentObservation:
    ecosystem: str
    name: str
    version: str
    purl: str
    source: str
    location: str
    dependency_type: str = "unknown"
    declared_version: str | None = None
    installed_version: str | None = None
    running_version: str | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyUsage:
    package: str
    file: str
    line: int
    symbol: str
    usage_type: str
    confidence: float
    caller: str | None = None
    evidence_id: str | None = None


@dataclass(frozen=True)
class VulnerableSymbol:
    """A symbol explicitly associated with an affected package by advisory data.

    ``confidence`` describes confidence in the advisory-to-package mapping. It is
    not a probability of exploitability or proof of runtime execution.
    """

    ecosystem: str
    package: str
    symbol: str
    vulnerability_id: str
    source: str
    confidence: float = 0.9
    module_path: str | None = None
    limitations: tuple[str, ...] = (
        "Advisory symbol metadata does not prove runtime binding or exploitability.",
    )


@dataclass(frozen=True)
class ExposureObservation:
    framework: str
    method: str
    route: str
    file: str
    line: int
    confidence: float
    handler: str | None = None
    evidence_id: str | None = None


@dataclass(frozen=True)
class ReachabilityResult:
    status: ReachabilityStatus
    confidence: float
    path: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    reason: str = ""
    limitations: tuple[str, ...] = ()
    path_edges: tuple[ReachabilityEdge, ...] = ()

    @property
    def explanation(self) -> str:
        """Return the human-readable explanation without breaking the existing reason field."""
        return self.reason


@dataclass(frozen=True)
class Finding:
    id: str
    vulnerability_id: str
    component_purl: str
    package_status: VersionMatchStatus
    reachability: ReachabilityResult
    evidence_ids: tuple[str, ...] = ()
