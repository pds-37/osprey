"""Backend adapter for the shared, read-only Osprey workspace scanner.

This module translates shared parser observations into the backend inventory contract.
It does not infer dependency versions from imports or claim process/runtime visibility.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple

from guardianos.storage.evidence import evidence_store
from osprey.core.models import EvidenceType
from osprey import __version__
from osprey.analyzers.source import SourceAnalysis
from osprey.scanner import scan_workspace

from guardianos.inventory.models import DependencyState, IngestionResult
from guardianos.inventory.service import inventory_service


LOCKFILES = {
    "cargo.lock",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pdm.lock",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}


def _observation_state(source_path: str) -> DependencyState:
    name = Path(source_path).name.lower()
    if name in LOCKFILES:
        return DependencyState.LOCKED
    if (
        name == "package.json"
        or name == "pyproject.toml"
        or name == "pipfile"
        or name.startswith("requirements") and name.endswith(".txt")
        or name.startswith("dockerfile")
        or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "go.mod", "cargo.toml"}
    ):
        return DependencyState.DECLARED
    return DependencyState.UNKNOWN


def scan_directory_manifests(
    target_dir: str | Path,
    app_name: Optional[str] = None,
    environment: str = "unknown",
    default_state: DependencyState = DependencyState.UNKNOWN,
    actor: str = "workspace-scanner",
    organization_id: str = "default-org",
) -> Tuple[IngestionResult, list[str]]:
    """Scan a workspace while preserving the original inventory adapter contract."""
    result, manifests, _source_analysis = scan_directory_manifests_with_analysis(
        target_dir=target_dir,
        app_name=app_name,
        environment=environment,
        default_state=default_state,
        actor=actor,
        organization_id=organization_id,
    )
    return result, manifests


def scan_directory_manifests_with_analysis(
    target_dir: str | Path,
    app_name: Optional[str] = None,
    environment: str = "unknown",
    default_state: DependencyState = DependencyState.UNKNOWN,
    actor: str = "workspace-scanner",
    organization_id: str = "default-org",
) -> Tuple[IngestionResult, list[str], SourceAnalysis]:
    """Scan a bounded workspace with the same manifest and source parser used by the CLI."""
    if default_state == DependencyState.RUNNING:
        raise ValueError("A local manifest scan cannot establish that a dependency is running")
    root_path = Path(target_dir).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError("The selected workspace path must be a directory")

    scan = scan_workspace(root_path, offline=True, evidence_store=evidence_store)
    selected_app = app_name or scan.app_name
    components: list[dict[str, object]] = []
    source_by_ref: dict[str, tuple[str, DependencyState, str, str | None, str | None, str | None, str | None]] = {}

    for index, component in enumerate(scan.components):
        try:
            absolute_source = Path(component.source_file).resolve(strict=True)
            relative_source = absolute_source.relative_to(root_path).as_posix()
            raw_source = absolute_source.read_bytes()
        except (OSError, ValueError):
            relative_source = ""
            raw_source = b""

        state = _observation_state(relative_source) if relative_source else DependencyState.UNKNOWN
        if state == DependencyState.UNKNOWN:
            state = default_state if default_state != DependencyState.UNKNOWN else DependencyState.UNKNOWN
        bom_ref = f"osprey-observation-{index}"
        properties = [
            {"name": "osprey:observation_state", "value": state.value},
            {"name": "osprey:dependency_type", "value": "development" if component.is_dev else "unknown"},
        ]
        if relative_source:
            properties.append({"name": "osprey:source_path", "value": relative_source})
        components.append({
            "type": "library" if component.ecosystem.lower() != "docker" else "container",
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "bom-ref": bom_ref,
            "properties": properties,
        })
        source_by_ref[bom_ref] = (
            relative_source,
            state,
            hashlib.sha256(raw_source).hexdigest() if raw_source else "",
            component.declared_version,
            component.locked_version,
            component.installed_version,
            component.installation_evidence_id,
        )

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": components,
    }
    result = inventory_service.ingest_sbom(
        raw_content=json.dumps(document, sort_keys=True),
        application=selected_app,
        environment=environment,
        default_state=DependencyState.UNKNOWN,
        actor=actor,
        organization_id=organization_id,
    )

    for index, component in enumerate(result.components):
        bom_ref = f"osprey-observation-{index}"
        (
            location, state, content_hash, declared_version, locked_version,
            installed_version, installation_evidence_id,
        ) = source_by_ref.get(
            bom_ref,
            ("", DependencyState.UNKNOWN, "", None, None, None, None),
        )
        if location and content_hash:
            evidence_type = EvidenceType.LOCKFILE if Path(location).name.lower() in LOCKFILES else EvidenceType.MANIFEST
            evidence = evidence_store.add(
                evidence_type=evidence_type,
                source="shared Osprey workspace scanner",
                location=location,
                content_hash=content_hash,
                confidence=0.98,
                metadata={
                    "component_purl": component.purl,
                    "observation_id": component.observation_id,
                    "state": state.value,
                    "analyzer": "Osprey",
                    "analyzer_version": __version__,
                    "analysis_type": "workspace_manifest_observation",
                },
            )
            component.evidence_ids.append(evidence.id)
        if scan.analysis_provenance_id:
            component.evidence_ids.append(scan.analysis_provenance_id)
        if scan.analysis_limitations_evidence_id:
            component.evidence_ids.append(scan.analysis_limitations_evidence_id)
        if scan.analysis_provenance_id:
            component.source = "workspace"
            component.location = location
            component.state = state
            component.declared_version = declared_version or (
                component.version if state == DependencyState.DECLARED else None
            )
            component.locked_version = locked_version or (
                component.version if state == DependencyState.LOCKED else None
            )
            component.installed_version = installed_version
            if installation_evidence_id:
                component.evidence_ids.append(installation_evidence_id)
            inventory_service.save_component(component)

    result.summary["manifests"] = scan.manifests
    result.summary["shared_scan_evidence_records"] = len(scan.evidence)
    result.summary["inventory_engine"] = "shared Osprey scanner"
    result.summary["installed_observations"] = sum(
        component.installed_version is not None for component in result.components
    )
    result.summary["runtime_observations"] = 0
    result.summary["runtime_collection"] = "UNAVAILABLE"
    result.summary["runtime_limitation"] = (
        "RUNTIME OBSERVATION UNAVAILABLE: no instrumented application process was supplied."
    )
    result.summary["analysis_provenance_id"] = scan.analysis_provenance_id
    result.summary["analysis_limitations_evidence_id"] = scan.analysis_limitations_evidence_id
    result.summary["source_file_count"] = len(scan.source_analysis.files_scanned) if scan.source_analysis else 0
    result.summary["analysis_limitations_count"] = len(scan.source_analysis.errors) if scan.source_analysis else 0
    if scan.source_analysis is None:  # Defensive: a scan should always return its analysis object.
        raise RuntimeError("shared Osprey scanner did not return source analysis")
    return result, scan.manifests, scan.source_analysis
