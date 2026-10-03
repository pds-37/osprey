"""Upstream change monitoring service coordinating detection and inventory impact."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store
from guardianos.inventory.service import inventory_service
from guardianos.upstream.detector import analyze_commit_heuristics
from guardianos.upstream.models import ChangeClassification, CommitRecord

_commits_db: Dict[str, CommitRecord] = {}


class UpstreamMonitorService:
    """Monitors upstream commits, releases, and changelogs for early security fixes."""

    def __init__(self) -> None:
        self.graph = get_graph_store()
        self._seed_default_commits()

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
            confidence=confidence,
            detected_signals=signals,
            reasoning=reasoning,
            potential_fixed_version=potential_fixed_version
        )
        _commits_db[record.id] = record

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

    def _seed_default_commits(self) -> None:
        """Seed flagship libheif security commit demonstration."""
        if "e31a196ec2b07d6b38c353b3df8d3dbb4cfae977" not in _commits_db:
            self.ingest_commit(
                repository="strukturag/libheif",
                commit_sha="e31a196ec2b07d6b38c353b3df8d3dbb4cfae977",
                component_name="libheif",
                author="Dirk Farin <dirk.farin@gmail.com>",
                message="Fix integer conversion in overlay calculation and add bounds check before memory allocation",
                diff_summary="@@ -421,7 +421,8 @@ int parse_overlay(struct heif_image* img) {\n- uint32_t alloc_sz = (uint32_t)(w * h * bpp);\n+ if (w > MAX_DIM || h > MAX_DIM) return -1;\n+ size_t alloc_sz = safe_multiply(w, h, bpp);\n+ char* buf = malloc(alloc_sz);",
                files_changed=["libheif/heif_image.cc", "libheif/box.cc"],
                potential_fixed_version="1.19.8"
            )

    def clear(self) -> None:
        _commits_db.clear()


upstream_service = UpstreamMonitorService()
