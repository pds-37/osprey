"""Patch Propagation Tracker service coordinating lifecycle analysis."""

from typing import Dict, List, Optional
from guardianos.graph.builder import get_graph_store
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.propagation.models import PatchPropagationRecord
from guardianos.propagation.tracker import evaluate_patch_propagation

_propagation_db: Dict[str, PatchPropagationRecord] = {}


class PropagationService:
    """Service tracking the 6-stage propagation lifecycle of upstream fixes to production."""

    def __init__(self) -> None:
        self.graph = get_graph_store()

    def evaluate_all(self) -> List[PatchPropagationRecord]:
        """Evaluate patch propagation across all active vulnerability findings."""
        findings = intel_service.list_findings()
        results = []

        for finding in findings:
            comp = inventory_service.get_component(finding.component_purl)
            if not comp:
                continue

            record = evaluate_patch_propagation(finding=finding, component=comp)
            _propagation_db[record.id] = record
            results.append(record)

            # Correlate in Knowledge Graph
            stage_node_id = f"stage:{record.bottleneck_stage.value}"
            self.graph.add_node(
                node_id=stage_node_id,
                label="PropagationStage",
                properties={
                    "stage": record.bottleneck_stage.value,
                    "is_blocked": True,
                    "bottleneck_for": record.component_name
                }
            )
            self.graph.add_edge(
                source_id=f"vuln:{finding.vulnerability_id}",
                target_id=stage_node_id,
                relation="BLOCKED_AT_STAGE",
                properties={"component": record.component_name}
            )

        return results

    def list_records(self, component: Optional[str] = None) -> List[PatchPropagationRecord]:
        records = list(_propagation_db.values())
        if not records:
            # Auto-evaluate if empty
            records = self.evaluate_all()
        if component:
            records = [r for r in records if r.component_name.lower() == component.lower()]
        return records

    def get_record(self, record_id: str) -> Optional[PatchPropagationRecord]:
        return _propagation_db.get(record_id)

    def clear(self) -> None:
        _propagation_db.clear()


propagation_service = PropagationService()
