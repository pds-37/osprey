"""Exposure service managing runtime endpoints and reachability profiles."""

from typing import Dict, List, Optional
import json
from guardianos.exposure.analyzer import evaluate_component_exposure
from guardianos.exposure.models import (
    AuthRequirement,
    DataProcessingType,
    EndpointProfile,
    ExposureProfile,
    NetworkExposure,
)
from guardianos.graph.builder import get_graph_store
from guardianos.inventory.service import inventory_service
from guardianos.storage.evidence import evidence_store
from osprey.core.models import EvidenceType
from guardianos.storage.sqlite import state_store

_endpoints_db: Dict[str, EndpointProfile] = {
    key: EndpointProfile.model_validate(value)
    for key, value in state_store.list("exposures").items()
}


class ExposureService:
    """Manages endpoint catalog, ingress exposures, and graph routing."""

    def __init__(self) -> None:
        self.graph = get_graph_store()

    def register_endpoint(self, ep: EndpointProfile, *, demo_fixture: bool = False) -> EndpointProfile:
        source = "DEMO_FIXTURE" if demo_fixture else "USER_INPUT"
        ep = ep.model_copy(update={"evidence_source": source, "evidence_ids": []})
        record = evidence_store.add(
            evidence_type=EvidenceType.USER_INPUT,
            source=source,
            location=ep.id,
            content=json.dumps(ep.model_dump(mode="json"), sort_keys=True),
            confidence=0.25 if demo_fixture else 0.5,
            metadata={"assertion_type": "endpoint_configuration", "endpoint_id": ep.id},
        )
        ep = ep.model_copy(update={"evidence_ids": [record.id]})
        _endpoints_db[ep.id] = ep
        state_store.put("exposures", ep.id, ep)

        # Correlate in Knowledge Graph
        # 1. Internet entry node
        if ep.network_exposure == NetworkExposure.INTERNET_FACING:
            self.graph.add_node("node:Internet", "Internet", {"name": "Public Internet", "is_attacker_origin": True})
            self.graph.add_node(ep.id, "Endpoint", {
                "name": ep.path,
                "service": ep.service,
                "auth": ep.auth_requirement.value,
                "public": ep.is_public
            })
            self.graph.add_edge("node:Internet", ep.id, "ROUTES_TO", {"auth": ep.auth_requirement.value})

        # 2. Service node
        service_node_id = f"service:{ep.service}"
        self.graph.add_node(service_node_id, "Service", {"name": ep.service})
        self.graph.add_edge(ep.id, service_node_id, "ROUTES_TO", {})

        # 3. Connect Service to components
        for comp_name in ep.connected_components:
            matching_comps = inventory_service.list_components(search=comp_name)
            for c in matching_comps:
                if c.name.lower() == comp_name.lower():
                    self.graph.add_edge(service_node_id, c.purl, "INVOKES", {})

        return ep

    def get_component_exposure(self, purl_or_name: str) -> Optional[ExposureProfile]:
        comp = inventory_service.get_component(purl_or_name)
        if not comp:
            comps = inventory_service.list_components(search=purl_or_name)
            if comps:
                comp = comps[0]
        if not comp:
            # Preserve uncertainty when no inventory observation exists.
            from guardianos.inventory.models import Component as Comp, Ecosystem, DependencyState as DS
            stub = Comp(
                id=f"pkg:generic/{purl_or_name}@unknown",
                name=purl_or_name,
                ecosystem=Ecosystem.GENERIC,
                version="unknown",
                purl=f"pkg:generic/{purl_or_name}@unknown",
                state=DS.UNKNOWN,
                application="unknown",
                environment="unknown"
            )
            return evaluate_component_exposure(component=stub, matching_endpoints=[])

        # Find endpoints mapped to this component or its application
        matching_eps = [
            ep for ep in _endpoints_db.values()
            if comp.name in ep.connected_components or ep.service.lower() in comp.application.lower()
        ]

        return evaluate_component_exposure(component=comp, matching_endpoints=matching_eps)

    def list_endpoints(self) -> List[EndpointProfile]:
        return list(_endpoints_db.values())

    def clear(self) -> None:
        _endpoints_db.clear()
        state_store.clear("exposures")


exposure_service = ExposureService()
