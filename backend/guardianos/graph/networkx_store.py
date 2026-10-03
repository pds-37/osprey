"""In-memory NetworkX implementation of GraphStore for development, testing, and fallback."""

import networkx as nx
from typing import Any, Dict, List, Optional
from guardianos.graph.store import GraphEdge, GraphNode, GraphPayload, GraphStore


class NetworkXGraphStore:
    """Zero-dependency graph store implementation backed by NetworkX."""

    def __init__(self) -> None:
        self.g = nx.DiGraph()

    def add_node(self, node_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> None:
        props = properties or {}
        if self.g.has_node(node_id):
            self.g.nodes[node_id].update(props)
            self.g.nodes[node_id]["label"] = label
        else:
            self.g.add_node(node_id, label=label, **props)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> None:
        props = properties or {}
        # Ensure source and target nodes exist with generic label if not yet present
        if not self.g.has_node(source_id):
            self.add_node(source_id, "Resource", {})
        if not self.g.has_node(target_id):
            self.add_node(target_id, "Resource", {})

        self.g.add_edge(source_id, target_id, relation=relation, **props)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        if not self.g.has_node(node_id):
            return None
        data = dict(self.g.nodes[node_id])
        label = data.pop("label", "Node")
        return GraphNode(id=node_id, label=label, properties=data)

    def get_subgraph(self, root_id: str, max_depth: int = 3) -> GraphPayload:
        if not self.g.has_node(root_id):
            return GraphPayload()

        # BFS expansion in both directions up to max_depth
        visited_nodes = {root_id}
        current_level = {root_id}
        
        for _ in range(max_depth):
            next_level = set()
            for n in current_level:
                # Successors and Predecessors
                next_level.update(self.g.successors(n))
                next_level.update(self.g.predecessors(n))
            new_nodes = next_level - visited_nodes
            if not new_nodes:
                break
            visited_nodes.update(new_nodes)
            current_level = new_nodes

        sub_g = self.g.subgraph(visited_nodes)
        
        nodes: List[GraphNode] = []
        for n, d in sub_g.nodes(data=True):
            props = dict(d)
            label = props.pop("label", "Node")
            nodes.append(GraphNode(id=n, label=label, properties=props))

        edges: List[GraphEdge] = []
        for u, v, d in sub_g.edges(data=True):
            props = dict(d)
            relation = props.pop("relation", "RELATES_TO")
            edges.append(GraphEdge(source=u, target=v, relation=relation, properties=props))

        return GraphPayload(
            nodes=nodes,
            edges=edges,
            summary={"root_id": root_id, "node_count": len(nodes), "edge_count": len(edges)}
        )

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6
    ) -> List[List[Dict[str, Any]]]:
        if not self.g.has_node(source_id) or not self.g.has_node(target_id):
            return []

        paths = []
        try:
            for simple_path in nx.all_simple_paths(self.g, source=source_id, target=target_id, cutoff=max_depth):
                path_details = []
                for i in range(len(simple_path)):
                    node_id = simple_path[i]
                    node_data = self.g.nodes[node_id]
                    edge_data = None
                    if i < len(simple_path) - 1:
                        next_node = simple_path[i + 1]
                        edge_data = self.g.get_edge_data(node_id, next_node)
                    path_details.append({
                        "node_id": node_id,
                        "label": node_data.get("label", "Node"),
                        "edge_to_next": edge_data.get("relation") if edge_data else None,
                        "properties": {k: v for k, v in node_data.items() if k != "label"}
                    })
                paths.append(path_details)
        except Exception:
            pass
        return paths

    def get_all(self, limit: int = 500) -> GraphPayload:
        nodes: List[GraphNode] = []
        for n, d in list(self.g.nodes(data=True))[:limit]:
            props = dict(d)
            label = props.pop("label", "Node")
            nodes.append(GraphNode(id=n, label=label, properties=props))

        edges: List[GraphEdge] = []
        for u, v, d in list(self.g.edges(data=True))[:limit]:
            props = dict(d)
            relation = props.pop("relation", "RELATES_TO")
            edges.append(GraphEdge(source=u, target=v, relation=relation, properties=props))

        return GraphPayload(
            nodes=nodes,
            edges=edges,
            summary={"total_nodes": self.g.number_of_nodes(), "total_edges": self.g.number_of_edges()}
        )

    def clear(self) -> None:
        self.g.clear()
