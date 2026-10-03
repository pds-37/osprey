"""CycloneDX SBOM parser supporting specifications 1.4 and 1.5 in JSON format."""

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


def parse_cyclonedx(
    data: Dict[str, Any],
    application: str = "default-app",
    environment: str = "production",
    default_state: DependencyState = DependencyState.INSTALLED
) -> IngestionResult:
    spec_version = str(data.get("specVersion", "1.4"))
    sbom_id = str(data.get("serialNumber", f"urn:uuid:{uuid.uuid4()}"))

    components: List[Component] = []
    relationships: List[DependencyRelationship] = []
    ref_to_purl: Dict[str, str] = {}

    # 1. Process root metadata component if present (e.g. application or container)
    metadata = data.get("metadata", {})
    root_component_data = metadata.get("component")
    root_purl = None
    if root_component_data:
        r_name = root_component_data.get("name", application)
        r_version = root_component_data.get("version", "1.0.0")
        r_type = root_component_data.get("type", "application")
        r_purl = root_component_data.get("purl")
        
        eco = Ecosystem.DOCKER if r_type == "container" else Ecosystem.GENERIC
        if not r_purl:
            r_purl = build_canonical_purl(eco, r_name, r_version)

        ref_id = root_component_data.get("bom-ref", r_purl)
        ref_to_purl[ref_id] = r_purl
        root_purl = r_purl

        components.append(
            Component(
                id=r_purl,
                name=r_name,
                ecosystem=eco,
                version=r_version,
                purl=r_purl,
                environment=environment,
                application=application,
                state=default_state,
                properties={"type": r_type, "is_root": True}
            )
        )

    # 2. Process all components
    raw_components = data.get("components", [])
    for comp in raw_components:
        name = comp.get("name", "unknown")
        version = comp.get("version", "0.0.0")
        purl = comp.get("purl")
        comp_type = comp.get("type", "library")

        # Determine ecosystem
        if purl:
            eco, parsed_name, parsed_version, _ = parse_purl(purl)
            name = parsed_name or name
            version = parsed_version or version
        else:
            eco = normalize_ecosystem(comp.get("group") or comp_type)
            purl = build_canonical_purl(eco, name, version)

        bom_ref = comp.get("bom-ref", purl)
        ref_to_purl[bom_ref] = purl

        # Extract checksum
        checksum = None
        hashes = comp.get("hashes", [])
        if hashes:
            checksum = f"{hashes[0].get('alg', 'SHA256')}:{hashes[0].get('content', '')}"

        # Extract licenses
        licenses_list = []
        for lic in comp.get("licenses", []):
            if "license" in lic:
                lic_obj = lic["license"]
                lic_name = lic_obj.get("id") or lic_obj.get("name")
                if lic_name:
                    licenses_list.append(lic_name)

        component_obj = Component(
            id=purl,
            name=name,
            ecosystem=eco,
            version=version,
            purl=purl,
            checksum=checksum,
            environment=environment,
            application=application,
            state=default_state,
            licenses=licenses_list,
            properties={"type": comp_type, "bom_ref": bom_ref}
        )
        components.append(component_obj)

    # 3. Process dependency graph relationships
    raw_dependencies = data.get("dependencies", [])
    for dep in raw_dependencies:
        parent_ref = dep.get("ref")
        parent_purl = ref_to_purl.get(parent_ref, parent_ref)
        depends_on = dep.get("dependsOn", [])
        for child_ref in depends_on:
            child_purl = ref_to_purl.get(child_ref, child_ref)
            if parent_purl and child_purl:
                relationships.append(
                    DependencyRelationship(
                        source_purl=parent_purl,
                        target_purl=child_purl,
                        relationship_type="DEPENDS_ON",
                        state=default_state
                    )
                )

    # If root exists and no dependencies defined, link root to all components
    if root_purl and not raw_dependencies:
        for c in components:
            if c.purl != root_purl:
                relationships.append(
                    DependencyRelationship(
                        source_purl=root_purl,
                        target_purl=c.purl,
                        relationship_type="CONTAINS" if "container" in root_purl else "DEPENDS_ON",
                        state=default_state
                    )
                )

    return IngestionResult(
        sbom_id=sbom_id,
        format=SBOMFormat.CYCLONEDX,
        spec_version=spec_version,
        application=application,
        environment=environment,
        components_count=len(components),
        relationships_count=len(relationships),
        components=components,
        relationships=relationships,
        summary={"root_purl": root_purl, "format": "CycloneDX"}
    )
