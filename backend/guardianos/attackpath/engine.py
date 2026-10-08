"""Graph traversal engine constructing end-to-end attack paths."""

from typing import List
from guardianos.attackpath.models import (
    AttackPath,
    AttackPathNode,
    AttackPathStatus,
    NodeRole,
)
from guardianos.graph.builder import get_graph_store
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service


def construct_attack_paths(*, include_demo_fixtures: bool = False) -> List[AttackPath]:
    """
    Traverse the Knowledge Graph starting from external entry points, passing through
    exposed vulnerable components, and ending at reachable high-value target assets.
    """
    # The legacy graph traversal below contains only one seeded demo scenario. It is
    # never evidence for an ordinary workspace scan or API recalculation.
    if not include_demo_fixtures:
        return []

    graph = get_graph_store()
    findings = intel_service.list_findings()
    paths: List[AttackPath] = []

    if not findings:
        return []

    # Ensure cloud and IAM target nodes exist in the graph for demonstration and traversal
    target_cloud_id = "cloud:s3-customer-media"
    sa_id = "iam:image-service-sa"
    graph.add_node(target_cloud_id, "CloudResource", {
        "name": "s3://customer-media-production",
        "type": "S3_BUCKET",
        "sensitivity": "CONFIDENTIAL"
    })
    graph.add_node(sa_id, "ServiceAccount", {
        "name": "k8s-image-service-sa",
        "permissions": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    })
    graph.add_edge("service:image-service", sa_id, "ASSUMES_ROLE", {})
    graph.add_edge(sa_id, target_cloud_id, "CAN_ACCESS", {})

    # Deduplicate & aggregate findings by component PURL
    findings_by_comp: dict[str, list] = {}
    for finding in findings:
        findings_by_comp.setdefault(finding.component_purl, []).append(finding)

    for comp_purl, comp_findings in findings_by_comp.items():
        comp = inventory_service.get_component(comp_purl)
        if not comp:
            continue

        severities = [f.severity.value for f in comp_findings]
        is_critical = "CRITICAL" in severities
        is_high = "HIGH" in severities

        # Only map attack paths for High or Critical vulnerabilities
        if is_critical or is_high:
            highest_sev = "CRITICAL" if is_critical else "HIGH"
            fixed_version = next((f.fixed_version for f in comp_findings if f.fixed_version), "latest")
            vuln_ids = list(dict.fromkeys(f.vulnerability_id for f in comp_findings))
            primary_vuln = vuln_ids[0]
            vuln_desc = f"{primary_vuln} (+{len(vuln_ids)-1} more)" if len(vuln_ids) > 1 else primary_vuln

            # Step 1: Internet
            node_internet = AttackPathNode(
                id="node:Internet",
                label="Public Internet",
                role=NodeRole.ENTRY_POINT,
                description="Unauthenticated adversary on the public internet",
                evidence={"protocol": "HTTPS", "ingress": "Public"}
            )

            # Step 2: Public Route / Ingress
            node_ep = AttackPathNode(
                id="ep-public-ingress",
                label="Public Service Route",
                role=NodeRole.ROUTE,
                description="Unauthenticated internet-facing endpoint routing to service",
                evidence={"auth": "None", "method": "HTTP", "url": "/"}
            )

            # Step 3: Application Service
            node_svc = AttackPathNode(
                id=f"service:{comp.application}",
                label=comp.application,
                role=NodeRole.SERVICE,
                description=f"Service '{comp.application}' loading dependency {comp.name}",
                evidence={"environment": comp.environment}
            )

            # Step 4: Vulnerable Library
            node_comp = AttackPathNode(
                id=comp.purl,
                label=f"{comp.name} @ {comp.version}",
                role=NodeRole.VULNERABLE_COMPONENT,
                description=f"Package affected by {vuln_desc} ({len(vuln_ids)} vulnerabilities)",
                evidence={
                    "vulnerabilities": vuln_ids,
                    "severity": highest_sev,
                    "installed_version": comp.version,
                    "fixed_version": fixed_version
                }
            )

            # Step 5: Execution Primitive tailored to component type
            c_name_lower = comp.name.lower()
            if any(k in c_name_lower for k in ["heif", "image", "pillow", "media", "graphic"]):
                prim_desc = "Heap buffer overflow or decoder memory corruption during untrusted media processing"
            elif any(k in c_name_lower for k in ["uvicorn", "fastapi", "express", "hasura", "server", "http"]):
                prim_desc = "HTTP request smuggling, header injection, or server worker compromise"
            elif any(k in c_name_lower for k in ["jwt", "jose", "auth", "crypto", "token"]):
                prim_desc = "Cryptographic signature bypass or token forgery leading to privilege escalation"
            else:
                prim_desc = f"Remote code execution or memory safety violation in {comp.name}"

            node_rce = AttackPathNode(
                id=f"primitive:exploit-{comp.name}",
                label=f"Exploitation Primitive ({highest_sev})",
                role=NodeRole.EXECUTION_PRIMITIVE,
                description=prim_desc,
                evidence={"cvss": 9.8 if is_critical else 7.5, "vulnerabilities_count": len(vuln_ids)}
            )

            # Step 6: Privilege Transition (IAM / Service Account)
            node_iam = AttackPathNode(
                id=sa_id,
                label="Workload Identity (IAM)",
                role=NodeRole.PRIVILEGE_TRANSITION,
                description="Assumed container identity with access to sensitive cloud storage",
                evidence={"permissions": ["s3:GetObject", "s3:PutObject"]}
            )

            # Step 7: Target Resource
            node_target = AttackPathNode(
                id=target_cloud_id,
                label="s3://customer-media-production",
                role=NodeRole.HIGH_VALUE_TARGET,
                description="Target cloud storage containing sensitive production data",
                evidence={"data_classification": "Confidential / Production"}
            )

            path_nodes = [
                node_internet,
                node_ep,
                node_svc,
                node_comp,
                node_rce,
                node_iam,
                node_target
            ]

            step_edges = [
                {"source": node_internet.id, "target": node_ep.id, "label": "Network Traffic"},
                {"source": node_ep.id, "target": node_svc.id, "label": "Dispatches To"},
                {"source": node_svc.id, "target": node_comp.id, "label": "Invokes Dependency"},
                {"source": node_comp.id, "target": node_rce.id, "label": "Triggers Vulnerability"},
                {"source": node_rce.id, "target": node_iam.id, "label": "Inherits Identity"},
                {"source": node_iam.id, "target": node_target.id, "label": "Exfiltrates Data"}
            ]

            path_id = f"path-{comp.name}-{comp.version}"
            attack_path = AttackPath(
                id=path_id,
                name=f"Potential Ingress Compromise via {comp.name} {comp.version}",
                entry_point="Internet (POST /upload)",
                vulnerable_component=comp.purl,
                vulnerability_id=primary_vuln,
                target_resource="s3://customer-media-production",
                nodes=path_nodes,
                step_edges=step_edges,
                exploitation_condition=f"Unauthenticated request triggers {primary_vuln} in {comp.name} (Upgrade to >= {fixed_version})",
                privilege_transitions=["Container User -> Workload Identity"],
                evidence=[
                    f"Component {comp.name} {comp.version} has {len(vuln_ids)} vulnerabilities ({primary_vuln}).",
                    "Service routes traffic to this component.",
                    "Workload identity has access to target cloud resources."
                ],
                confidence=0.95,
                status=AttackPathStatus.OPEN,
                recommended_remediation=f"Upgrade {comp.name} to version >= {fixed_version} in manifest."
                ,fixture=True
            )
            paths.append(attack_path)

            # Add AttackPath node into Knowledge Graph
            graph.add_node(
                node_id=path_id,
                label="AttackPath",
                properties={
                    "name": attack_path.name,
                    "status": attack_path.status.value,
                    "confidence": attack_path.confidence
                }
            )
            graph.add_edge(node_internet.id, path_id, "ORIGINATES", {})
            graph.add_edge(path_id, target_cloud_id, "COMPROMISES", {})

    return paths
