"""Small helpers for deterministic, versioned analyzer provenance records."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Any

from osprey import __version__
from osprey.core.evidence import EvidenceStore, canonical_json, content_digest
from osprey.core.models import Evidence, EvidenceType, ReachabilityResult
from osprey.risk import RiskAssessment, RiskEvidence


def _language_counts(files: list[str]) -> dict[str, int]:
    suffix_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
    }
    counts: dict[str, int] = {}
    for file in files:
        language = suffix_map.get(PurePosixPath(file.replace("\\", "/")).suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))


def record_analysis_run(
    store: EvidenceStore,
    analysis: Any,
    *,
    analysis_type: str,
) -> Evidence:
    """Record bounded analyzer context without storing a machine-specific root path."""
    files = list(analysis.files_scanned)
    languages = _language_counts(files)
    file_set_hash = content_digest(canonical_json(sorted(analysis.file_evidence.values())))
    metadata = {
        "analyzer": "Osprey",
        "analyzer_version": __version__,
        "analysis_type": analysis_type,
        "source_file_count": len(files),
        "language_counts": languages,
        "max_graph_depth": int(analysis.max_graph_depth),
        "source_file_set_hash": file_set_hash,
    }
    content = canonical_json({
        "source_file_count": len(files),
        "language_counts": languages,
        "source_file_set_hash": file_set_hash,
        "limitation_count": len(analysis.errors),
        "traversal_truncated": bool(analysis.traversal_truncated),
    })
    return store.add(
        evidence_type=EvidenceType.ANALYSIS_RUN,
        source="Osprey bounded static analyzer",
        location="analysis run",
        content=content,
        metadata=metadata,
    )


def record_reachability(
    store: EvidenceStore,
    result: ReachabilityResult,
    *,
    finding_id: str,
    analysis_run_id: str,
) -> tuple[Evidence, Evidence | None]:
    """Persist a reachability conclusion and, when present, its limitations."""
    path_edges = [asdict(edge) for edge in result.path_edges]
    payload = {
        "status": result.status.value,
        "confidence": result.confidence,
        "path": list(result.path),
        "path_edges": path_edges,
        "reason": result.reason,
        "limitations": list(result.limitations),
        "basis_evidence_ids": list(result.evidence),
    }
    evidence = store.add(
        evidence_type=EvidenceType.REACHABILITY,
        source="Osprey bounded reachability analyzer",
        location=f"finding:{finding_id}",
        content=canonical_json(payload),
        confidence=result.confidence,
        metadata={
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_type": "source_reachability",
            "analysis_run_id": analysis_run_id,
            "finding_id": finding_id,
            # Keep normalized conclusion data available to evidence readers. The
            # source files themselves remain represented by hashes and IDs only.
            "observed": payload,
        },
    )
    limitation_evidence = None
    if result.limitations:
        limitation_evidence = store.add(
            evidence_type=EvidenceType.ANALYSIS_LIMITATION,
            source="Osprey bounded reachability analyzer",
            location=f"finding:{finding_id}",
            content=canonical_json(list(result.limitations)),
            metadata={
                "analyzer": "Osprey",
                "analyzer_version": __version__,
                "analysis_run_id": analysis_run_id,
                "finding_id": finding_id,
                "scope": "reachability",
                "observed": {"limitations": list(result.limitations)},
            },
        )
    return evidence, limitation_evidence


def record_analysis_limitations(
    store: EvidenceStore,
    limitations: list[str],
    *,
    analysis_run_id: str,
) -> Evidence | None:
    """Persist parser/read/graph limitations without treating them as findings."""
    if not limitations:
        return None
    normalized = canonical_json(list(limitations))
    sample = [item[:512] for item in limitations[:64]]
    return store.add(
        evidence_type=EvidenceType.ANALYSIS_LIMITATION,
        source="Osprey bounded static analyzer",
        location="analysis run",
        content=canonical_json({
            "limitation_count": len(limitations),
            "limitations_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        }),
        metadata={
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_run_id": analysis_run_id,
            "scope": "source_analysis",
            "limitation_count": len(limitations),
            "limitations_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            "sample_truncated": len(limitations) > len(sample) or any(len(item) > 512 for item in limitations[:64]),
            "observed": {"limitations_sample": sample},
        },
    )


def record_risk_assessment(
    store: EvidenceStore,
    inputs: RiskEvidence,
    assessment: RiskAssessment,
    *,
    finding_id: str,
) -> Evidence:
    """Persist the exact normalized input and output from the shared risk engine."""
    payload = {
        "inputs": asdict(inputs),
        "assessment": {
            "score": assessment.score,
            "risk_level": assessment.risk_level,
            "decision": assessment.decision,
            "factors": [asdict(factor) for factor in assessment.factors],
            "explanation": assessment.explanation,
            "limitations": list(assessment.limitations),
            "evidence_coverage": assessment.evidence_coverage,
            "evidence_ids": list(assessment.evidence_ids),
        },
    }
    return store.add(
        evidence_type=EvidenceType.RISK,
        source="Osprey shared deterministic risk engine",
        location=f"finding:{finding_id}",
        content=canonical_json(payload),
        metadata={
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_type": "risk_assessment",
            "finding_id": finding_id,
            "observed": payload,
        },
    )
