"""Read-only deterministic data access helpers for evidence summaries."""

from typing import Any, Dict, List, Optional
from guardianos.attackpath.service import attack_path_service
from guardianos.exposure.service import exposure_service
from guardianos.intel.feed_data import vuln_registry
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.propagation.service import propagation_service
from guardianos.upstream.service import upstream_service


def tool_get_component_lineage(purl_or_name: str) -> Dict[str, Any]:
    """Retrieve canonical component metadata and ancestry chain in dependency tree."""
    comp = inventory_service.get_component(purl_or_name)
    if not comp:
        comps = inventory_service.list_components(search=purl_or_name)
        comp = comps[0] if comps else None
    if not comp:
        return {"error": f"Component '{purl_or_name}' not found in active inventory"}

    lineage = inventory_service.get_component_lineage(comp.purl)
    return {
        "component": comp.model_dump(),
        "lineage": lineage
    }


def tool_get_vulnerability_intel(vuln_id: str) -> Dict[str, Any]:
    """Retrieve a configured local advisory record, if present."""
    adv = vuln_registry.get_advisory(vuln_id)
    if not adv:
        return {"error": f"Advisory '{vuln_id}' not found in feed registry"}
    return adv.model_dump()


def tool_get_runtime_exposure(component_name: str) -> Dict[str, Any]:
    """Retrieve endpoint metadata; this does not inspect runtime ingress."""
    profile = exposure_service.get_component_exposure(component_name)
    if not profile:
        return {"network_exposure": "UNKNOWN", "endpoints": [], "error": f"No exposure profile mapped to '{component_name}'"}
    return profile.model_dump()


def tool_get_attack_paths(component_name: str) -> List[Dict[str, Any]]:
    """Return stored path records; this function does not discover cloud paths."""
    paths = attack_path_service.list_paths()
    matching = [p.model_dump() for p in paths if component_name.lower() in p.name.lower() or component_name in p.vulnerable_component]
    return matching


def tool_get_upstream_changes(component_name: str) -> List[Dict[str, Any]]:
    """Retrieve upstream commits and suspicious security fix detections."""
    commits = upstream_service.list_commits(component=component_name)
    return [c.model_dump() for c in commits]


def tool_get_patch_propagation(component_name: str) -> Optional[Dict[str, Any]]:
    """Retrieve 6-stage patch propagation tracker and bottleneck analysis."""
    records = propagation_service.list_records(component=component_name)
    if records:
        return records[0].model_dump()
    return None
