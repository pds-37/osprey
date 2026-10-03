"""Exposure service managing runtime endpoints and reachability profiles."""

from typing import Dict, List, Optional
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

_endpoints_db: Dict[str, EndpointProfile] = {}


class ExposureService:
    """Manages endpoint catalog, ingress exposures, and graph routing."""

    def __init__(self) -> None:
        self.graph = get_graph_store()
        self._seed_default_endpoints()

    def register_endpoint(self, ep: EndpointProfile) -> EndpointProfile:
        _endpoints_db[ep.id] = ep

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
            return None

        # Find endpoints mapped to this component or its application
        matching_eps = [
            ep for ep in _endpoints_db.values()
            if comp.name in ep.connected_components or ep.service.lower() in comp.application.lower()
        ]

        return evaluate_component_exposure(component=comp, matching_endpoints=matching_eps)

    def list_endpoints(self) -> List[EndpointProfile]:
        return list(_endpoints_db.values())

    def _seed_default_endpoints(self) -> None:
        """Seed flagship public upload endpoint connected to ImageMagick and libheif."""
        default_ep = EndpointProfile(
            id="ep-media-upload",
            path="POST /upload",
            service="image-service",
            network_exposure=NetworkExposure.INTERNET_FACING,
            auth_requirement=AuthRequirement.NONE,
            processing_type=DataProcessingType.PARSER_UNTRUSTED_INPUT,
            is_public=True,
            connected_components=["imagemagick", "libheif"]
        )
        self.register_endpoint(default_ep)

    def clear(self) -> None:
        _endpoints_db.clear()
        self._seed_default_endpoints()


exposure_service = ExposureService()
