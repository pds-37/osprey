"""Tests for deterministic, bounded, and tamper-evident provenance records."""

import hashlib
import json
from dataclasses import replace

import pytest

from guardianos.storage.evidence import PersistentEvidenceStore
from guardianos.storage.sqlite import SQLiteDocumentStore
from osprey.core.evidence import (
    MAX_CONTENT_BYTES,
    EvidenceStore,
    canonical_json,
    verify_record,
)
from osprey.core.models import EvidenceType
from osprey.core.models import ReachabilityResult, ReachabilityStatus
from osprey.core.provenance import record_analysis_limitations, record_reachability, record_risk_assessment
from osprey.risk import RiskEvidence, calculate_risk


def test_content_hash_and_id_are_stable_for_canonical_equivalent_metadata():
    left = EvidenceStore().add(
        evidence_type=EvidenceType.MANIFEST,
        source="test parser",
        location="requirements.txt",
        content="demo==1.2.3",
        metadata={"package": "demo", "version": "1.2.3"},
    )
    right = EvidenceStore().add(
        evidence_type=EvidenceType.MANIFEST,
        source="test parser",
        location="requirements.txt",
        content="demo==1.2.3",
        metadata={"version": "1.2.3", "package": "demo"},
    )

    assert left.id == right.id
    assert left.content_hash == right.content_hash == hashlib.sha256(b"demo==1.2.3").hexdigest()
    assert verify_record(left) is True
    assert left.record_hash != right.record_hash  # Observation timestamps are included in the envelope hash.


def test_meaningful_content_or_confidence_change_changes_evidence_identity():
    store = EvidenceStore()
    first = store.add(
        evidence_type=EvidenceType.IMPORT,
        source="static analyzer",
        location="src/parser.py:4",
        content="import example",
        confidence=0.8,
    )
    changed_content = store.add(
        evidence_type=EvidenceType.IMPORT,
        source="static analyzer",
        location="src/parser.py:4",
        content="import another",
        confidence=0.8,
    )
    changed_confidence = store.add(
        evidence_type=EvidenceType.IMPORT,
        source="static analyzer",
        location="src/parser.py:4",
        content="import example",
        confidence=0.7,
    )

    assert len({first.content_hash, changed_content.content_hash, changed_confidence.content_hash}) == 2
    assert first.id != changed_content.id
    assert first.id != changed_confidence.id


def test_content_hash_mismatch_and_malformed_metadata_are_rejected():
    store = EvidenceStore()
    with pytest.raises(ValueError, match="does not match"):
        store.add(
            evidence_type=EvidenceType.SBOM,
            source="upload",
            location="bundle.json",
            content="original",
            content_hash="0" * 64,
        )

    with pytest.raises(ValueError, match="JSON-compatible"):
        canonical_json({"bad": object()})
    with pytest.raises(ValueError, match="keys must be strings"):
        canonical_json({1: "not a JSON object key"})
    with pytest.raises(ValueError, match="non-finite"):
        canonical_json({"score": float("nan")})
    with pytest.raises(ValueError, match="metadata"):
        store.add(
            evidence_type=EvidenceType.USER_INPUT,
            source="test",
            location="input",
            metadata={"large": "x" * 70_000},
        )
    with pytest.raises(ValueError, match="size limit"):
        store.add(
            evidence_type=EvidenceType.VULNERABILITY_ADVISORY,
            source="OSV",
            location="CVE-test",
            content="x" * (MAX_CONTENT_BYTES + 1),
        )


def test_record_and_source_content_tampering_are_detected():
    store = EvidenceStore()
    record = store.add(
        evidence_type=EvidenceType.SOURCE_FILE,
        source="Osprey",
        location="src/parser.py",
        content="def parse(): pass\n",
    )

    assert store.verify_content(record, "def parse(): pass\n") is True
    assert store.verify_content(record, "def parse(): return None\n") is False
    tampered_metadata = replace(record, metadata={**record.metadata, "analyzer_version": "forged"})
    tampered_digest = replace(record, content_hash="0" * 64)
    assert store.verify_record(tampered_metadata) is False
    assert store.verify_record(tampered_digest) is False


def test_evidence_round_trips_through_sqlite_and_legacy_records_remain_readable(tmp_path):
    database = SQLiteDocumentStore(str(tmp_path / "evidence.sqlite3"))
    first_store = PersistentEvidenceStore(database)
    record = first_store.add(
        evidence_type=EvidenceType.VERSION,
        source="Osprey version matcher",
        location="CVE-test",
        content=canonical_json({"observed_version": "1.2.3", "status": "AFFECTED"}),
        metadata={
            "package": "demo",
            "affected_ranges": ["< 1.2.4"],
            "observed": {"observed_version": "1.2.3", "status": "AFFECTED"},
        },
    )
    database.put("evidence", "ev-legacy", {
        "id": "ev-legacy",
        "type": "MANIFEST",
        "source": "legacy import",
        "location": "requirements.txt",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "confidence": 0.5,
        "content_hash": "legacy-purl-version-value",
        "metadata": {},
    })

    reopened = PersistentEvidenceStore(database)
    stored = reopened.get(record.id)
    legacy = reopened.get("ev-legacy")
    assert stored is not None
    assert stored.record_hash == record.record_hash
    assert stored.metadata["observed"]["status"] == "AFFECTED"
    assert reopened.integrity_status(stored) == "VERIFIED"
    assert stored.content == ""  # Raw input is not retained.
    assert legacy is not None
    assert legacy.content_hash == "legacy-purl-version-value"
    assert reopened.integrity_status(legacy) == "UNVERIFIED_LEGACY"
    database.close()


def test_malformed_sqlite_json_is_reported_without_crashing(tmp_path):
    database = SQLiteDocumentStore(str(tmp_path / "corrupt-evidence.sqlite3"))
    with database._connection:
        database._connection.execute(
            "INSERT INTO records(record_type, record_id, payload, updated_at) VALUES(?, ?, ?, ?)",
            ("evidence", "ev-corrupt", "{not-json", "2026-01-01T00:00:00+00:00"),
        )

    assert "ev-corrupt" not in database.list("evidence")
    assert ("evidence", "ev-corrupt") in database.corrupt_records
    assert database.get("evidence", "ev-corrupt") is None
    database.close()


def test_path_traversal_is_kept_as_inert_data_and_never_opened():
    store = EvidenceStore()
    record = store.add(
        evidence_type=EvidenceType.SOURCE_FILE,
        source="submitted source bundle",
        location="../../secrets.txt",
        content="not opened by evidence storage",
    )
    assert record.location == "../../secrets.txt"
    assert store.verify_record(record) is True


def test_reachability_and_risk_observations_are_available_in_evidence_records():
    store = EvidenceStore()
    analysis = store.add(
        evidence_type=EvidenceType.ANALYSIS_RUN,
        source="test analyzer",
        location="analysis run",
        content="run",
    )
    reachability = ReachabilityResult(
        status=ReachabilityStatus.UNKNOWN,
        confidence=0.0,
        reason="dynamic dispatch could not be resolved",
        limitations=("dynamic dispatch",),
    )
    reach_record, limit_record = record_reachability(
        store, reachability, finding_id="finding-1", analysis_run_id=analysis.id
    )
    assert reach_record.metadata["observed"]["status"] == "UNKNOWN"
    assert reach_record.metadata["observed"]["reason"] == "dynamic dispatch could not be resolved"
    assert limit_record is not None
    assert limit_record.metadata["observed"]["limitations"] == ["dynamic dispatch"]

    inputs = RiskEvidence(
        severity="UNKNOWN",
        cvss_score=None,
        epss_score=None,
        kev_listed=None,
        version_status="AFFECTED",
        dependency_present=True,
        exposure="UNKNOWN",
        reachability_status="UNKNOWN",
        limitations=("dynamic dispatch",),
    )
    assessment = calculate_risk(inputs)
    risk_record = record_risk_assessment(store, inputs, assessment, finding_id="finding-1")
    observed = risk_record.metadata["observed"]
    assert observed["inputs"]["cvss_score"] is None
    assert observed["inputs"]["epss_score"] is None
    assert observed["inputs"]["kev_listed"] is None
    assert observed["assessment"]["decision"] == assessment.decision
    assert observed["assessment"]["explanation"] == assessment.explanation
    assert store.verify_record(risk_record) is True


def test_sensitive_metadata_keys_are_not_required_for_source_content_protection():
    store = EvidenceStore()
    # Source text is never retained, even if it contains a credential-like value.
    record = store.add(
        evidence_type=EvidenceType.SOURCE_FILE,
        source="static analyzer",
        location="src/config.py",
        content='TOKEN = "example-secret-value"',
    )
    assert record.content == ""
    assert "example-secret-value" not in json.dumps(record.metadata)


def test_large_analysis_limitations_are_bounded_and_retain_full_list_digest():
    store = EvidenceStore()
    limitations = [f"source/file-{index}.py: unsupported dynamic syntax" for index in range(900)]
    record = record_analysis_limitations(store, limitations, analysis_run_id="run-1")
    assert record is not None
    assert record.metadata["limitation_count"] == 900
    assert record.metadata["sample_truncated"] is True
    assert len(record.metadata["observed"]["limitations_sample"]) == 64
    assert record.metadata["limitations_sha256"] == hashlib.sha256(
        canonical_json(limitations).encode("utf-8")
    ).hexdigest()
    assert verify_record(record) is True
