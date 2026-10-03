"""Neo4j GraphStore implementation using official neo4j driver."""

import logging
from typing import Any, Dict, List, Optional
from neo4j import GraphDatabase
from guardianos.graph.store import GraphEdge, GraphNode, GraphPayload

logger = logging.getLogger("guardianos.graph.neo4j")


class Neo4jGraphStore:
    """Enterprise Neo4j graph store implementation."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        self.uri = uri
        self.user = user
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def add_node(self, node_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> None:
        props = properties or {}
        # Sanitize label to alphanumeric only
        safe_label = "".join(c for c in label if c.isalnum() or c == "_") or "Node"
        query = (
            f"MERGE (n:`{safe_label}` {{id: $id}}) "
            f"SET n += $props"
        )
        with self.driver.session() as session:
            session.run(query, id=node_id, props=props)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> None:
        props = properties or {}
        safe_rel = "".join(c for c in relation if c.isalnum() or c == "_") or "RELATES_TO"
        query = (
            f"MERGE (a {{id: $source_id}}) "
            f"MERGE (b {{id: $target_id}}) "
            f"MERGE (a)-[r:`{safe_rel}`]->(b) "
            f"SET r += $props"
        )
        with self.driver.session() as session:
            session.run(query, source_id=source_id, target_id=target_id, props=props)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        query = "MATCH (n {id: $id}) RETURN labels(n) as labels, properties(n) as props LIMIT 1"
        with self.driver.session() as session:
            result = session.run(query, id=node_id)
            record = result.single()
            if not record:
                return None
            labels = record["labels"]
            label = labels[0] if labels else "Node"
            props = dict(record["props"])
            return GraphNode(id=node_id, label=label, properties=props)

    def get_subgraph(self, root_id: str, max_depth: int = 3) -> GraphPayload:
        query = (
            f"MATCH path = (root {{id: $root_id}})-[*1..{max_depth}]-(neighbor) "
            "UNWIND nodes(path) as n "
            "UNWIND relationships(path) as r "
            "RETURN collect(distinct n) as nodes, collect(distinct r) as rels"
        )
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        with self.driver.session() as session:
            result = session.run(query, root_id=root_id)
            record = result.single()
            if record:
                for n in record["nodes"]:
                    nid = n.get("id", str(n.id))
                    lbl = list(n.labels)[0] if n.labels else "Node"
                    nodes.append(GraphNode(id=nid, label=lbl, properties=dict(n)))
                for r in record["rels"]:
                    edges.append(
                        GraphEdge(
                            source=r.start_node.get("id", str(r.start_node.id)),
                            target=r.end_node.get("id", str(r.end_node.id)),
                            relation=r.type,
                            properties=dict(r)
                        )
                    )
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
        query = (
            f"MATCH p = (a {{id: $source_id}})-[*1..{max_depth}]->(b {{id: $target_id}}) "
            "RETURN p LIMIT 25"
        )
        paths = []
        with self.driver.session() as session:
            result = session.run(query, source_id=source_id, target_id=target_id)
            for record in result:
                path = record["p"]
                path_details = []
                for i, node in enumerate(path.nodes):
                    nid = node.get("id", str(node.id))
                    lbl = list(node.labels)[0] if node.labels else "Node"
                    edge_type = None
                    if i < len(path.relationships):
                        edge_type = path.relationships[i].type
                    path_details.append({
                        "node_id": nid,
                        "label": lbl,
                        "edge_to_next": edge_type,
                        "properties": dict(node)
                    })
                paths.append(path_details)
        return paths

    def get_all(self, limit: int = 500) -> GraphPayload:
        query = (
            f"MATCH (n) "
            f"OPTIONAL MATCH (n)-[r]->(m) "
            f"RETURN n, r, m LIMIT {limit}"
        )
        nodes_dict: Dict[str, GraphNode] = {}
        edges_list: List[GraphEdge] = []
        with self.driver.session() as session:
            result = session.run(query)
            for rec in result:
                n = rec["n"]
                if n:
                    nid = n.get("id", str(n.id))
                    if nid not in nodes_dict:
                        lbl = list(n.labels)[0] if n.labels else "Node"
                        nodes_dict[nid] = GraphNode(id=nid, label=lbl, properties=dict(n))
                r = rec["r"]
                m = rec["m"]
                if r and m:
                    mid = m.get("id", str(m.id))
                    if mid not in nodes_dict:
                        lbl_m = list(m.labels)[0] if m.labels else "Node"
                        nodes_dict[mid] = GraphNode(id=mid, label=lbl_m, properties=dict(m))
                    edges_list.append(
                        GraphEdge(
                            source=nid,
                            target=mid,
                            relation=r.type,
                            properties=dict(r)
                        )
                    )
        return GraphPayload(
            nodes=list(nodes_dict.values()),
            edges=edges_list,
            summary={"node_count": len(nodes_dict), "edge_count": len(edges_list)}
        )

    def clear(self) -> None:
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
