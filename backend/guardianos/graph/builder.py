"""Graph construction and singleton factory."""

import logging
from typing import Optional
from guardianos.core.config import settings
from guardianos.graph.store import GraphPayload, GraphStore
from guardianos.graph.networkx_store import NetworkXGraphStore
from guardianos.graph.neo4j_store import Neo4jGraphStore
from guardianos.inventory.models import Ecosystem, IngestionResult

logger = logging.getLogger("guardianos.graph.builder")

_global_graph_store: Optional[GraphStore] = None


def get_graph_store() -> GraphStore:
    """Return configured GraphStore instance with automatic fallback."""
    global _global_graph_store
    if _global_graph_store is None:
        if settings.USE_IN_MEMORY_GRAPH:
            _global_graph_store = NetworkXGraphStore()
            logger.info("Initialized in-memory NetworkX GraphStore")
        else:
            try:
                _global_graph_store = Neo4jGraphStore(
                    uri=settings.NEO4J_URI or "bolt://localhost:7687",
                    user=settings.NEO4J_USER,
                    password=settings.NEO4J_PASSWORD
                )
                logger.info("Connected to Neo4j GraphStore")
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j ({e}). Falling back to in-memory NetworkX.")
                _global_graph_store = NetworkXGraphStore()
    return _global_graph_store


def populate_graph_from_ingestion(
    result: IngestionResult,
    store: Optional[GraphStore] = None
) -> int:
    """Ingest components and relationships into the Knowledge Graph."""
    graph = store or get_graph_store()
    nodes_added = 0

    # 1. Add components as nodes
    for comp in result.components:
        label = "Package"
        if comp.ecosystem == Ecosystem.DOCKER:
            label = "Container"
        elif comp.properties.get("is_root"):
            label = "Application"

        graph.add_node(
            node_id=comp.purl,
            label=label,
            properties={
                "name": comp.name,
                "version": comp.version,
                "ecosystem": comp.ecosystem.value,
                "purl": comp.purl,
                "environment": comp.environment,
                "application": comp.application,
                "state": comp.state.value,
                "licenses": comp.licenses,
                "checksum": comp.checksum
            }
        )
        nodes_added += 1

    # 2. Add relationships as edges
    for rel in result.relationships:
        graph.add_edge(
            source_id=rel.source_purl,
            target_id=rel.target_purl,
            relation=rel.relationship_type,
            properties={
                "state": rel.state.value,
                **rel.metadata
            }
        )

    return nodes_added


def format_graph_for_ui(payload: GraphPayload) -> dict:
    """Format graph nodes and edges with visual styling for React/D3/Cytoscape."""
    type_color_map = {
        "Internet": "#ef4444",
        "Endpoint": "#f97316",
        "Service": "#3b82f6",
        "Application": "#6366f1",
        "Container": "#06b6d4",
        "Package": "#10b981",
        "Library": "#14b8a6",
        "CloudResource": "#8b5cf6",
        "Agent": "#ec4899",
        "Vulnerability": "#dc2626"
    }

    formatted_nodes = []
    for n in payload.nodes:
        color = type_color_map.get(n.label, "#64748b")
        formatted_nodes.append({
            "id": n.id,
            "label": n.properties.get("name", n.id),
            "type": n.label,
            "color": color,
            "version": n.properties.get("version", ""),
            "ecosystem": n.properties.get("ecosystem", ""),
            "state": n.properties.get("state", "INSTALLED"),
            "properties": n.properties
        })

    formatted_edges = []
    for e in payload.edges:
        formatted_edges.append({
            "source": e.source,
            "target": e.target,
            "label": e.relation,
            "properties": e.properties
        })

    return {
        "nodes": formatted_nodes,
        "edges": formatted_edges,
        "summary": payload.summary
    }
