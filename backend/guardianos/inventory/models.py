"""Inventory and Component data models adhering to GuardianOS specifications."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    DEBIAN = "debian"
    RPM = "rpm"
    GO = "golang"
    MAVEN = "maven"
    DOCKER = "docker"
    CARGO = "cargo"
    GENERIC = "generic"


class DependencyState(str, Enum):
    DECLARED = "DECLARED"    # Defined in manifest/lockfile (e.g., package.json, requirements.txt)
    INSTALLED = "INSTALLED"  # Installed in filesystem or container image (e.g. node_modules, /usr/lib)
    RUNNING = "RUNNING"      # Actively running in memory/production workload


class SBOMFormat(str, Enum):
    CYCLONEDX = "CycloneDX"
    SPDX = "SPDX"
    SYFT = "Syft"
    UNKNOWN = "Unknown"


class Component(BaseModel):
    id: str = Field(..., description="Canonical ID or PURL")
    name: str = Field(..., description="Component package name")
    ecosystem: Ecosystem = Field(default=Ecosystem.GENERIC, description="Package ecosystem")
    version: str = Field(..., description="Installed or declared version")
    purl: str = Field(..., description="Package URL standard identifier")
    source: Optional[str] = Field(None, description="Origin repository or package registry")
    checksum: Optional[str] = Field(None, description="SHA256 or package digest")
    parent_purls: list[str] = Field(default_factory=list, description="Immediate parents in dependency tree")
    environment: str = Field(default="production", description="Environment: production, staging, development")
    application: str = Field(default="default-app", description="Owning application")
    deployment: Optional[str] = Field(None, description="Associated workload or container deployment")
    owner: Optional[str] = Field(None, description="Owning team or engineer")
    state: DependencyState = Field(default=DependencyState.INSTALLED, description="Declared, Installed, or Running")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    licenses: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class DependencyRelationship(BaseModel):
    source_purl: str = Field(..., description="Source component/asset PURL or identifier")
    target_purl: str = Field(..., description="Target component/library PURL")
    relationship_type: str = Field(default="DEPENDS_ON", description="DEPENDS_ON, CONTAINS, BUILT_FROM, DEPLOYED_AS, BUILDS")
    state: DependencyState = Field(default=DependencyState.INSTALLED)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SBOMDocument(BaseModel):
    id: str = Field(..., description="Unique document ingestion ID")
    format: SBOMFormat = Field(..., description="Detected format (CycloneDX, SPDX, Syft)")
    spec_version: str = Field("unknown", description="Format specification version")
    application: str = Field("default-app", description="Target application name")
    environment: str = Field("production", description="Deployment environment")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    component_count: int = Field(default=0)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class IngestionResult(BaseModel):
    sbom_id: str
    format: SBOMFormat
    spec_version: str
    application: str
    environment: str
    components_count: int
    relationships_count: int
    components: list[Component] = Field(default_factory=list)
    relationships: list[DependencyRelationship] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
