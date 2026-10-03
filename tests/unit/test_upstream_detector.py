"""Unit tests for upstream change detection and security signal heuristics."""

from guardianos.upstream.detector import analyze_commit_heuristics
from guardianos.upstream.models import ChangeClassification
from guardianos.upstream.service import upstream_service


def test_suspicious_security_commit_detection():
    msg = "Fix integer conversion in overlay calculation and add bounds check"
    diff = "size_t alloc_sz = safe_multiply(w, h); void* buf = malloc(alloc_sz);"
    classification, confidence, signals, reasoning = analyze_commit_heuristics(msg, diff)

    assert classification == ChangeClassification.SUSPECTED_SECURITY_CHANGE
    assert confidence >= 0.70
    assert "integer conversion" in signals
    assert "bounds calculation" in signals
    assert "memory allocation" in signals


def test_benign_documentation_commit():
    msg = "Update README.md with formatting and typo fixes"
    classification, confidence, signals, reasoning = analyze_commit_heuristics(msg)

    assert classification == ChangeClassification.UNKNOWN
    assert confidence < 0.20
    assert len(signals) == 0


def test_upstream_service_ingest_and_graph_link():
    record = upstream_service.ingest_commit(
        repository="strukturag/libheif",
        commit_sha="testsha123456789",
        component_name="libheif",
        author="Dev",
        message="Prevent heap-buffer-overflow by adding input validation in parser",
        diff_summary="if (size > max) return -1;"
    )

    assert record.classification == ChangeClassification.SUSPECTED_SECURITY_CHANGE
    assert "buffer overflow" in record.detected_signals

    # Verify Commit node added to Graph
    node = upstream_service.graph.get_node("commit:testsha1")
    assert node is not None
    assert node.label == "Commit"
