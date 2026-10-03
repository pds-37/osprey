"""Inventory management service coordinating parsing, persistence, and graph updates."""

from typing import Dict, List, Optional
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

# In-memory storage stores (mirrored with SQL models in db layer)
_components_db: Dict[str, Component] = {}
_sboms_db: Dict[str, SBOMDocument] = {}


class InventoryService:
    """Enterprise Inventory and SBOM management service."""

    def __init__(self) -> None:
        self.graph = get_graph_store()

    def ingest_sbom(
        self,
        raw_content: str,
        application: str = "default-app",
        environment: str = "production",
        default_state: DependencyState = DependencyState.INSTALLED,
        actor: str = "system"
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
            environment=environment,
            component_count=result.components_count,
            raw_metadata=result.summary
        )
        _sboms_db[result.sbom_id] = sbom_doc

        # 3. Store components
        for comp in result.components:
            _components_db[comp.purl] = comp

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
        limit: int = 200
    ) -> List[Component]:
        comps = list(_components_db.values())
        if ecosystem:
            comps = [c for c in comps if c.ecosystem == ecosystem]
        if application:
            comps = [c for c in comps if c.application.lower() == application.lower()]
        if search:
            q = search.lower()
            comps = [c for c in comps if q in c.name.lower() or q in c.purl.lower()]
        return comps[:limit]

    def get_component(self, purl: str) -> Optional[Component]:
        return _components_db.get(purl)

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
        self.graph.clear()


inventory_service = InventoryService()
