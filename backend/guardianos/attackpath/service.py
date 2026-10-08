"""Attack Path service managing path recalculation and lifecycle state."""

from typing import Dict, List, Optional
from guardianos.attackpath.engine import construct_attack_paths
from guardianos.attackpath.models import AttackPath, AttackPathStatus
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store

_attack_paths_db: Dict[str, AttackPath] = {}


class AttackPathService:
    """Service tracking discovered adversary attack paths across the graph."""

    def __init__(self) -> None:
        self.graph = get_graph_store()

    def recalculate_paths(self, *, include_demo_fixtures: bool = False) -> List[AttackPath]:
        paths = construct_attack_paths(include_demo_fixtures=include_demo_fixtures)
        _attack_paths_db.clear()
        for p in paths:
            _attack_paths_db[p.id] = p

        if paths:
            record_audit_event(
                action="ATTACK_PATHS_DISCOVERED",
                target_type="AttackPath",
                target_id=f"count-{len(paths)}",
                actor="attack-path-engine",
                details={
                    "paths_count": len(paths),
                    "open_paths": [p.name for p in paths if p.status == AttackPathStatus.OPEN]
                }
            )
        return paths

    def list_paths(self, status: Optional[str] = None) -> List[AttackPath]:
        paths = list(_attack_paths_db.values())
        if not paths:
            paths = self.recalculate_paths()
        if status:
            paths = [p for p in paths if p.status.value.lower() == status.lower()]
        return paths

    def get_path(self, path_id: str) -> Optional[AttackPath]:
        return _attack_paths_db.get(path_id)

    def close_path(self, path_id: str, reason: str = "Remediation verified") -> Optional[AttackPath]:
        path = _attack_paths_db.get(path_id)
        if path:
            path.status = AttackPathStatus.CLOSED
            # Update Knowledge Graph
            self.graph.add_node(
                node_id=path.id,
                label="AttackPath",
                properties={"status": AttackPathStatus.CLOSED.value, "closure_reason": reason}
            )
            record_audit_event(
                action="ATTACK_PATH_CLOSED",
                target_type="AttackPath",
                target_id=path.id,
                actor="verification-engine",
                details={"reason": reason}
            )
        return path

    def clear(self) -> None:
        _attack_paths_db.clear()


attack_path_service = AttackPathService()
