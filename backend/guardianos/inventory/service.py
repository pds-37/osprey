"""Inventory management service coordinating parsing, persistence, and graph updates."""

from typing import Dict, List, Optional
from guardianos.storage.evidence import evidence_store
from guardianos.storage.sqlite import state_store
from osprey.core.models import EvidenceType
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store, populate_graph_from_ingestion
from guardianos.inventory.models import (
    Component,
    DependencyState,
    Ecosystem,
    IngestionResult,
    SBOMDocument,
)
from guardianos.inventory.parser import parse_sbom

# SQLite is the local source of truth. Dictionaries are process-local indexes rebuilt at startup.
_components_db: Dict[str, Component] = {
    key: Component.model_validate(value)
    for key, value in state_store.list("components").items()
}
_sboms_db: Dict[str, SBOMDocument] = {
    key: SBOMDocument.model_validate(value)
    for key, value in state_store.list("sboms").items()
}
_relationships_db: Dict[str, dict] = state_store.list("relationships")


class InventoryService:
    """Enterprise Inventory and SBOM management service."""

    def __init__(self) -> None:
        self.graph = get_graph_store()
        self._rebuild_graph()

    def _rebuild_graph(self) -> None:
        """Rehydrate the volatile graph from durable inventory observations."""
        for comp in _components_db.values():
            label = "Container" if comp.ecosystem == Ecosystem.DOCKER else (
                "Application" if comp.properties.get("is_root") else "Package"
            )
            self.graph.add_node(comp.purl, label, {
                "name": comp.name,
                "version": comp.version,
                "ecosystem": comp.ecosystem.value,
                "purl": comp.purl,
                "environment": comp.environment,
                "application": comp.application,
                "state": comp.state.value,
                "licenses": comp.licenses,
                "checksum": comp.checksum,
            })
        for payload in _relationships_db.values():
            self.graph.add_edge(
                payload["source_purl"], payload["target_purl"],
                payload.get("relationship_type", "DEPENDS_ON"),
                {"state": payload.get("state", "UNKNOWN"), **payload.get("metadata", {})},
            )

    def ingest_sbom(
        self,
        raw_content: str,
        application: str = "default-app",
        environment: str = "unknown",
        default_state: DependencyState = DependencyState.UNKNOWN,
        actor: str = "system",
        organization_id: str = "default-org",
    ) -> IngestionResult:
        # 1. Parse SBOM
        result = parse_sbom(
            raw_content=raw_content,
            application=application,
            environment=environment,
            default_state=default_state
        )

        # 2. Store SBOM metadata
        sbom_doc = SBOMDocument(
            id=result.sbom_id,
            format=result.format,
            spec_version=result.spec_version,
            application=application,
            organization_id=organization_id[:128],
            environment=environment,
            component_count=result.components_count,
            raw_metadata=result.summary
        )
        _sboms_db[result.sbom_id] = sbom_doc
        state_store.put("sboms", result.sbom_id, sbom_doc)

        # 3. Store components
        for comp in result.components:
            comp.organization_id = organization_id[:128]
            comp.source = comp.source or f"sbom:{result.sbom_id}"
            comp.location = comp.location or f"{result.sbom_id}:{comp.purl}"
            evidence = evidence_store.add(
                evidence_type=EvidenceType.SBOM,
                source=f"SBOM:{result.format.value}",
                location=comp.location,
                content=raw_content,
                metadata={
                    "sbom_id": result.sbom_id,
                    "component_purl": comp.purl,
                    "observation_id": comp.observation_id,
                    "analysis_type": "sbom_ingestion",
                    "provenance": "submitted_document",
                },
            )
            comp.evidence_ids.append(evidence.id)
            _components_db[comp.observation_id] = comp
            state_store.put("components", comp.observation_id, comp)

        for index, relationship in enumerate(result.relationships):
            relationship_id = f"{result.sbom_id}:{index}"
            payload = relationship.model_dump(mode="json")
            _relationships_db[relationship_id] = payload
            state_store.put("relationships", relationship_id, payload)

        # 4. Populate Knowledge Graph
        populate_graph_from_ingestion(result, store=self.graph)

        # 5. Record Audit Event
        record_audit_event(
            action="SBOM_INGESTED",
            target_type="SBOMDocument",
            target_id=result.sbom_id,
            actor=actor,
            details={
                "format": result.format.value,
                "application": application,
                "components_count": result.components_count,
                "relationships_count": result.relationships_count
            }
        )

        return result

    def list_components(
        self,
        ecosystem: Optional[Ecosystem] = None,
        search: Optional[str] = None,
        application: Optional[str] = None,
        limit: int = 200,
        organization_id: Optional[str] = None,
    ) -> List[Component]:
        comps = list(_components_db.values())
        if organization_id is not None:
            comps = [c for c in comps if c.organization_id == organization_id]
        if ecosystem:
            comps = [c for c in comps if c.ecosystem == ecosystem]
        if application:
            comps = [c for c in comps if c.application.lower() == application.lower()]
        if search:
            q = search.lower()
            comps = [c for c in comps if q in c.name.lower() or q in c.purl.lower()]
        return comps[:limit]

    def get_component(self, purl: str, organization_id: Optional[str] = None) -> Optional[Component]:
        direct = _components_db.get(purl)
        if direct is not None and (organization_id is None or direct.organization_id == organization_id):
            return direct
        return next((component for component in _components_db.values()
                     if component.purl == purl
                     and (organization_id is None or component.organization_id == organization_id)), None)

    def get_component_by_observation_id(self, observation_id: str) -> Optional[Component]:
        return _components_db.get(observation_id)

    def save_component(self, component: Component) -> None:
        """Persist an updated observation without merging it with sibling observations."""
        _components_db[component.observation_id] = component
        state_store.put("components", component.observation_id, component)

    def get_component_lineage(self, purl: str) -> dict:
        """Trace lineage from root applications or containers down to this component."""
        comp = self.get_component(purl)
        if not comp:
            return {"purl": purl, "ancestors": [], "found": False}

        # Query incoming relationships in the knowledge graph
        subgraph = self.graph.get_subgraph(purl, max_depth=5)
        return {
            "purl": purl,
            "component": comp.model_dump(),
            "subgraph": subgraph.model_dump(),
            "found": True
        }

    def list_sboms(self) -> List[SBOMDocument]:
        return list(_sboms_db.values())

    def get_sbom(self, sbom_id: str) -> Optional[SBOMDocument]:
        return _sboms_db.get(sbom_id)

    def clear(self) -> None:
        _components_db.clear()
        _sboms_db.clear()
        _relationships_db.clear()
        for record_type in ("components", "sboms", "relationships"):
            state_store.clear(record_type)
        evidence_store.clear()
        self.graph.clear()


inventory_service = InventoryService()
