"""SPDX SBOM parser supporting specifications 2.2 and 2.3 in JSON format."""

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


def parse_spdx(
    data: Dict[str, Any],
    application: str = "default-app",
    environment: str = "unknown",
    default_state: DependencyState = DependencyState.UNKNOWN
) -> IngestionResult:
    spec_version = str(data.get("spdxVersion", "SPDX-2.3"))
    sbom_id = str(data.get("SPDXID", f"SPDXRef-DOC-{uuid.uuid4()}"))

    components: List[Component] = []
    relationships: List[DependencyRelationship] = []
    spdx_id_to_purl: Dict[str, str] = {}

    packages = data.get("packages", [])
    for pkg in packages:
        spdx_id = pkg.get("SPDXID", "")
        name = pkg.get("name", "unknown")
        version = pkg.get("versionInfo", "0.0.0")
        
        # Look for purl in externalRefs
        purl = None
        for ext_ref in pkg.get("externalRefs", []):
            if ext_ref.get("referenceType", "").lower() == "purl":
                purl = ext_ref.get("referenceLocator")
                break

        if purl:
            eco, parsed_name, parsed_version, _ = parse_purl(purl)
            name = parsed_name or name
            version = parsed_version or version
        else:
            eco = normalize_ecosystem(pkg.get("originator") or pkg.get("supplier") or "generic")
            purl = build_canonical_purl(eco, name, version)

        spdx_id_to_purl[spdx_id] = purl

        # Checksums
        checksum = None
        checksums = pkg.get("checksums", [])
        if checksums:
            checksum = f"{checksums[0].get('algorithm', 'SHA256')}:{checksums[0].get('checksumValue', '')}"

        licenses_list = []
        concluded = pkg.get("licenseConcluded")
        if concluded and concluded != "NOASSERTION":
            licenses_list.append(concluded)

        components.append(
            Component(
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
                properties={"spdx_id": spdx_id, "supplier": pkg.get("supplier")}
            )
        )

    # Relationships
    for rel in data.get("relationships", []):
        src_id = rel.get("spdxElementId")
        tgt_id = rel.get("relatedSpdxElement")
        rel_type = rel.get("relationshipType", "DEPENDS_ON").upper()

        src_purl = spdx_id_to_purl.get(src_id)
        tgt_purl = spdx_id_to_purl.get(tgt_id)

        if src_purl and tgt_purl:
            canonical_rel = "DEPENDS_ON"
            if "CONTAIN" in rel_type:
                canonical_rel = "CONTAINS"
            elif "BUILD" in rel_type:
                canonical_rel = "BUILDS"
            
            relationships.append(
                DependencyRelationship(
                    source_purl=src_purl,
                    target_purl=tgt_purl,
                    relationship_type=canonical_rel,
                    state=default_state
                )
            )

    return IngestionResult(
        sbom_id=sbom_id,
        format=SBOMFormat.SPDX,
        spec_version=spec_version,
        application=application,
        environment=environment,
        components_count=len(components),
        relationships_count=len(relationships),
        components=components,
        relationships=relationships,
        summary={"packages_count": len(packages), "format": "SPDX"}
    )
