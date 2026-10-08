"""Upstream change monitoring service coordinating detection and inventory impact."""

from datetime import datetime, timezone
import json
from typing import Dict, List, Optional
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store
from guardianos.inventory.service import inventory_service
from guardianos.upstream.detector import analyze_commit_heuristics
from guardianos.upstream.models import ChangeClassification, CommitRecord
from guardianos.storage.evidence import evidence_store
from osprey.core.models import EvidenceType
from guardianos.storage.sqlite import state_store

_commits_db: Dict[str, CommitRecord] = {
    key: CommitRecord.model_validate(value)
    for key, value in state_store.list("upstream_commits").items()
}


class UpstreamMonitorService:
    """Monitors upstream commits, releases, and changelogs for early security fixes."""

    def __init__(self) -> None:
        self.graph = get_graph_store()

    def ingest_commit(
        self,
        repository: str,
        commit_sha: str,
        component_name: str,
        author: str,
        message: str,
        diff_summary: str = "",
        files_changed: Optional[List[str]] = None,
        potential_fixed_version: Optional[str] = None
    ) -> CommitRecord:
        files = files_changed or []
        classification, confidence, signals, reasoning = analyze_commit_heuristics(message, diff_summary)
        evidence = evidence_store.add(
            evidence_type=EvidenceType.USER_INPUT,
            source="user-supplied commit metadata",
            location=f"{repository}@{commit_sha}",
            content=json.dumps({"message": message, "diff_summary": diff_summary, "files_changed": files}, sort_keys=True),
            confidence=min(confidence, 0.5),
            metadata={"repository": repository, "commit_sha": commit_sha, "heuristic_only": True},
        )

        record = CommitRecord(
            id=commit_sha,
            commit_sha=commit_sha,
            repository=repository,
            component_name=component_name,
            author=author,
            timestamp=datetime.now(timezone.utc),
            message=message,
            diff_summary=diff_summary,
            files_changed=files,
            classification=classification,
            confidence=min(confidence, 0.5),
            detected_signals=signals,
            reasoning=reasoning,
            potential_fixed_version=potential_fixed_version,
            evidence_ids=[evidence.id],
        )
        _commits_db[record.id] = record
        state_store.put("upstream_commits", record.id, record)

        # Correlate in Knowledge Graph if suspicious or corroborated
        if classification == ChangeClassification.SUSPECTED_SECURITY_CHANGE:
            commit_node_id = f"commit:{commit_sha[:8]}"
            self.graph.add_node(
                node_id=commit_node_id,
                label="Commit",
                properties={
                    "sha": commit_sha,
                    "repository": repository,
                    "component_name": component_name,
                    "confidence": confidence,
                    "signals": signals,
                    "message": message[:80]
                }
            )

            # Link commit to any matching components currently in inventory
            comps = inventory_service.list_components(search=component_name)
            for c in comps:
                if c.name.lower() == component_name.lower():
                    self.graph.add_edge(
                        source_id=commit_node_id,
                        target_id=c.purl,
                        relation="FIXES_ISSUE_IN",
                        properties={"confidence": confidence}
                    )

            record_audit_event(
                action="SUSPECTED_SECURITY_CHANGE_DETECTED",
                target_type="Commit",
                target_id=commit_sha,
                actor="upstream-monitor",
                details={
                    "repository": repository,
                    "component": component_name,
                    "confidence": confidence,
                    "signals": signals
                }
            )

        return record

    def list_commits(self, component: Optional[str] = None) -> List[CommitRecord]:
        commits = list(_commits_db.values())
        if component:
            commits = [c for c in commits if c.component_name.lower() == component.lower()]
        return sorted(commits, key=lambda c: c.timestamp, reverse=True)

    def get_commit(self, sha: str) -> Optional[CommitRecord]:
        return _commits_db.get(sha)

    def clear(self) -> None:
        _commits_db.clear()
        state_store.clear("upstream_commits")


upstream_service = UpstreamMonitorService()
