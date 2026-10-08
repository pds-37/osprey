"""Syft JSON SBOM parser for container and host scans."""

import uuid
from typing import Any, Dict, List
from guardianos.inventory.models import (
    Component,
    DependencyRelationship,
    DependencyState,
    Ecosystem,
    IngestionResult,
    SBOMFormat,
)
from guardianos.inventory.normalizer import build_canonical_purl, normalize_ecosystem, parse_purl


def parse_syft(
    data: Dict[str, Any],
    application: str = "default-app",
    environment: str = "unknown",
    default_state: DependencyState = DependencyState.INSTALLED
) -> IngestionResult:
    sbom_id = str(data.get("id", f"syft-{uuid.uuid4()}"))
    spec_version = str(data.get("schema", {}).get("version", "1.0.0"))

    components: List[Component] = []
    relationships: List[DependencyRelationship] = []
    artifact_id_to_purl: Dict[str, str] = {}

    # 1. Identify source image or target
    source_info = data.get("source", {})
    target_name = source_info.get("target", application)
    target_type = source_info.get("type", "image")

    root_purl = None
    if target_name:
        root_eco = Ecosystem.DOCKER if target_type in ["image", "container"] else Ecosystem.GENERIC
        root_purl = build_canonical_purl(root_eco, target_name, "latest")
        components.append(
            Component(
                id=root_purl,
                name=target_name,
                ecosystem=root_eco,
                version="latest",
                purl=root_purl,
                environment=environment,
                application=application,
                state=DependencyState.INSTALLED,
                properties={"source_type": target_type, "is_root_container": True}
            )
        )

    # 2. Parse artifacts
    artifacts = data.get("artifacts", [])
    for art in artifacts:
        art_id = art.get("id", "")
        name = art.get("name", "unknown")
        version = art.get("version", "0.0.0")
        raw_type = art.get("type", "generic")
        purl = art.get("purl")

        if purl:
            eco, parsed_name, parsed_version, _ = parse_purl(purl)
            name = parsed_name or name
            version = parsed_version or version
        else:
            eco = normalize_ecosystem(raw_type)
            purl = build_canonical_purl(eco, name, version)

        artifact_id_to_purl[art_id] = purl

        # Licenses
        licenses_list = [lic.get("value", "") for lic in art.get("licenses", []) if lic.get("value")]

        comp_obj = Component(
            id=purl,
            name=name,
            ecosystem=eco,
            version=version,
            purl=purl,
            environment=environment,
            application=application,
            state=default_state,
            licenses=licenses_list,
            properties={"syft_type": raw_type, "syft_id": art_id}
        )
        components.append(comp_obj)

        # If we have a root container, container CONTAINS this package
        if root_purl:
            relationships.append(
                DependencyRelationship(
                    source_purl=root_purl,
                    target_purl=purl,
                    relationship_type="CONTAINS",
                    state=default_state
                )
            )

    # 3. Parse Syft relationships if present
    for rel in data.get("artifactRelationships", []):
        parent_id = rel.get("parent")
        child_id = rel.get("child")
        parent_purl = artifact_id_to_purl.get(parent_id)
        child_purl = artifact_id_to_purl.get(child_id)
        if parent_purl and child_purl:
            relationships.append(
                DependencyRelationship(
                    source_purl=parent_purl,
                    target_purl=child_purl,
                    relationship_type="DEPENDS_ON",
                    state=default_state
                )
            )

    return IngestionResult(
        sbom_id=sbom_id,
        format=SBOMFormat.SYFT,
        spec_version=spec_version,
        application=application,
        environment=environment,
        components_count=len(components),
        relationships_count=len(relationships),
        components=components,
        relationships=relationships,
        summary={"source_target": target_name, "format": "Syft"}
    )
