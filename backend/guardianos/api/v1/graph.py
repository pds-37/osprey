"""Dependency Knowledge Graph API endpoints."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from guardianos.graph.builder import format_graph_for_ui, get_graph_store

router = APIRouter(prefix="/graph", tags=["Knowledge Graph"])


class PathQueryRequest(BaseModel):
    source_id: str = Field(..., description="Source node identifier")
    target_id: str = Field(..., description="Target node identifier")
    max_depth: int = Field(6, ge=1, le=10)


@router.get("/data")
async def get_graph_data(limit: int = Query(500, ge=10, le=2000)):
    """Retrieve graph nodes and edges styled for interactive UI visualization."""
    store = get_graph_store()
    raw_payload = store.get_all(limit=limit)
    return format_graph_for_ui(raw_payload)


@router.get("/subgraph")
async def get_subgraph(
    node_id: str = Query(..., description="Root node identifier or PURL"),
    depth: int = Query(3, ge=1, le=5)
):
    """Retrieve subgraph centered around a specific component or asset."""
    store = get_graph_store()
    raw_payload = store.get_subgraph(root_id=node_id, max_depth=depth)
    if not raw_payload.nodes:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found in graph")
    return format_graph_for_ui(raw_payload)


@router.post("/paths")
async def find_graph_paths(query: PathQueryRequest):
    """Traverse and discover all structural paths between two nodes."""
    store = get_graph_store()
    paths = store.find_paths(source_id=query.source_id, target_id=query.target_id, max_depth=query.max_depth)
    return {
        "source_id": query.source_id,
        "target_id": query.target_id,
        "paths_count": len(paths),
        "paths": paths
    }
