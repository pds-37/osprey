"""Graph store interface and protocol."""

from typing import Any, Dict, List, Optional, Protocol, Tuple
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str = Field(..., description="Unique node identifier or PURL")
    label: str = Field(..., description="Node label: Application, Container, Package, Library, Service, Endpoint, CloudResource, Agent, Vulnerability")
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    relation: str = Field(..., description="Relationship type: DEPENDS_ON, CONTAINS, BUILT_FROM, DEPLOYED_AS, BUILDS, ROUTES_TO, CAN_ACCESS, AFFECTED_BY")
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphPayload(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class GraphStore(Protocol):
    """Protocol for graph operations in GuardianOS."""

    def add_node(self, node_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> None:
        ...

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> None:
        ...

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        ...

    def get_subgraph(self, root_id: str, max_depth: int = 3) -> GraphPayload:
        ...

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6
    ) -> List[List[Dict[str, Any]]]:
        ...

    def get_all(self, limit: int = 500) -> GraphPayload:
        ...

    def clear(self) -> None:
        ...
