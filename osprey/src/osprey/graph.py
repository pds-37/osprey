"""NetworkX supply chain and attack path graph representation.

GRAPH STRUCTURE:
- Application -> Service -> Component -> Vulnerability
- Directed edges trace the exact dependency and exposure lineage.

Assumptions and Limitations:
- Graph edges represent package dependency and deployment containment.
- Path tracing highlights the structural route from entrypoints down to vulnerable packages.
"""

from __future__ import annotations

from typing import List, Optional

import networkx as nx

from osprey.models import Component, Finding, Service


class SupplyChainGraph:
    """Manages the in-memory directed graph of software components and vulnerabilities."""

    def __init__(self, app_name: str = "app"):
        self.app_name = app_name
        self.graph = nx.DiGraph()
        self.app_node_id = f"app:{app_name}"
        self.graph.add_node(
            self.app_node_id,
            node_type="application",
            name=app_name,
            label=f"Application: {app_name}",
        )

    def add_service(self, service: Service) -> str:
        snode_id = f"svc:{service.name}"
        self.graph.add_node(
            snode_id,
            node_type="service",
            name=service.name,
            ports=service.ports,
            ports_declared=service.ports_declared,
            exposure=service.exposure.level if service.exposure else "unknown",
            label=f"Service: {service.name}",
        )
        self.graph.add_edge(self.app_node_id, snode_id, relation="CONTAINS")
        return snode_id

    def add_component(self, component: Component, service_id: Optional[str] = None) -> str:
        cnode_id = f"comp:{component.observation_id}"
        if cnode_id not in self.graph:
            self.graph.add_node(
                cnode_id,
                node_type="component",
                name=component.name,
                version=component.version,
                ecosystem=component.ecosystem,
                purl=component.purl,
                observation_id=component.observation_id,
                source_file=component.source_file,
                is_dev=component.is_dev,
                label=f"{component.name}@{component.version}",
            )

        parent_id = service_id or self.app_node_id
        if not self.graph.has_edge(parent_id, cnode_id):
            self.graph.add_edge(parent_id, cnode_id, relation="DEPENDS_ON")

        return cnode_id

    def add_finding(self, finding: Finding) -> str:
        vnode_id = f"vuln:{finding.id}"
        self.graph.add_node(
            vnode_id,
            node_type="vulnerability",
            vulnerability_id=finding.vulnerability_id,
            risk_tier=finding.risk_tier,
            firing_rule=finding.firing_rule,
            cvss_score=finding.cvss_score,
            epss_score=finding.epss_score,
            in_cisa_kev=finding.in_cisa_kev,
            fix=finding.fix_status.minimal_safe_version,
            exposure=finding.exposure.level,
            label=f"{finding.vulnerability_id} ({finding.risk_tier})",
        )

        cnode_id = f"comp:{finding.component.observation_id}"
        if cnode_id in self.graph:
            self.graph.add_edge(cnode_id, vnode_id, relation="AFFECTED_BY")

        return vnode_id

    def get_evidence_path(self, finding_id: str) -> List[str]:
        """Find the shortest structural path from Application to Vulnerability."""
        vnode_id = f"vuln:{finding_id}"
        if vnode_id not in self.graph or self.app_node_id not in self.graph:
            return []

        try:
            path = nx.shortest_path(self.graph, source=self.app_node_id, target=vnode_id)
            return [self.graph.nodes[n].get("label", n) for n in path]
        except nx.NetworkXNoPath:
            return []
        except Exception:
            return []
