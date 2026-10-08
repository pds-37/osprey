"""Bounded installation inspection and opt-in runtime instrumentation tests."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
import sys

from osprey.core.evidence import EvidenceStore
from osprey.core.models import EvidenceType
from osprey.runtime import (
    InstallationInspector,
    RuntimeInstrumentation,
    runtime_evidence_freshness,
    summarize_runtime_state,
)


def _install_python_fixture(site_packages):
    site_packages.mkdir(parents=True)
    (site_packages / "fixture_runtime.py").write_text(
        "def decode(value):\n    return value[::-1]\n", encoding="utf-8"
    )
    dist_info = site_packages / "fixture_runtime-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: fixture-runtime\nVersion: 1.0.0\n\n",
        encoding="utf-8",
    )
    (dist_info / "top_level.txt").write_text("fixture_runtime\n", encoding="utf-8")
    (dist_info / "RECORD").write_text(
        "fixture_runtime.py,,\nfixture_runtime-1.0.0.dist-info/METADATA,,\n",
        encoding="utf-8",
    )


def test_node_installation_requires_matching_local_package_metadata(tmp_path):
    inspector = InstallationInspector(tmp_path)
    assert inspector.inspect("express", "npm") is None

    package = tmp_path / "node_modules" / "express"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        '{"name":"express","version":"4.19.0"}', encoding="utf-8"
    )
    inspector = InstallationInspector(tmp_path)
    observed = inspector.inspect("express", "npm")
    assert observed is not None
    assert observed.version == "4.19.0"
    assert observed.location == "node_modules/express/package.json"
    assert inspector.inspect("../../outside", "npm") is None


def test_python_installation_reads_only_project_virtual_environment_metadata(tmp_path):
    site = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    _install_python_fixture(site)
    inspector = InstallationInspector(tmp_path)
    observed = inspector.inspect("fixture_runtime", "pypi")
    assert observed is not None
    assert observed.package_name == "fixture-runtime"
    assert observed.version == "1.0.0"
    assert observed.location.endswith("fixture_runtime-1.0.0.dist-info/METADATA")
    assert inspector.inspect("not-installed", "pypi") is None


def test_runtime_instrumentation_observes_loaded_module_and_successful_symbol_call(tmp_path, monkeypatch):
    site = tmp_path / "site-packages"
    _install_python_fixture(site)
    monkeypatch.syspath_prepend(str(site))
    importlib.invalidate_caches()
    module = importlib.import_module("fixture_runtime")
    store = EvidenceStore()
    observer = RuntimeInstrumentation(store, environment="local-test")

    try:
        loaded = observer.observe_loaded_module(
            "fixture_runtime", "fixture-runtime", finding_id="find-fixture-1"
        )
        assert loaded.type == EvidenceType.RUNTIME_OBSERVATION
        assert loaded.metadata["observed"]["state"] == "LOADED"
        assert str(site) not in loaded.location

        invoke = observer.instrument_symbol("fixture_runtime", "decode")
        assert invoke("hello") == "olleh"
        records = store.list()
        exercised = next(
            item for item in records
            if item.metadata.get("observed", {}).get("state") == "EXERCISED"
        )
        snapshot = summarize_runtime_state(
            store,
            package_name="fixture-runtime",
            ecosystem="pypi",
            version="1.0.0",
            finding_id="find-fixture-1",
        )
        assert snapshot.states["LOADED"] == "OBSERVED"
        assert snapshot.states["EXERCISED"] == "OBSERVED"
        assert loaded.id in snapshot.evidence_ids
        assert exercised.id in snapshot.evidence_ids
    finally:
        sys.modules.pop("fixture_runtime", None)


def test_absent_malformed_and_tampered_runtime_evidence_remain_unknown():
    store = EvidenceStore()
    absent = summarize_runtime_state(
        store, package_name="fixture-runtime", ecosystem="pypi", version="1.0.0"
    )
    assert all(absent.states[key] == "UNKNOWN" for key in ("DECLARED", "INSTALLED", "LOADED", "EXERCISED"))
    assert any("not NOT_PRESENT" in text for text in absent.limitations)

    malformed = store.add(
        evidence_type=EvidenceType.RUNTIME_OBSERVATION,
        source="untrusted input",
        location="event",
        content="malformed event",
        metadata={"collector": "untrusted", "observed": {
            "package_name": "fixture-runtime", "ecosystem": "pypi", "version": "1.0.0",
            "state": "EXPLOITED", "process_id": "1", "module_name": "../bad",
        }},
    )
    malformed_snapshot = summarize_runtime_state(
        store, package_name="fixture-runtime", ecosystem="pypi", version="1.0.0"
    )
    assert malformed_snapshot.states["LOADED"] == "UNKNOWN"
    assert malformed.id not in malformed_snapshot.evidence_ids

    tampered = replace(malformed, metadata={**malformed.metadata, "collector": "explicit_python_module_probe"})
    store._records[malformed.id] = tampered
    tampered_snapshot = summarize_runtime_state(
        store, package_name="fixture-runtime", ecosystem="pypi", version="1.0.0"
    )
    assert tampered_snapshot.states["LOADED"] == "UNKNOWN"


def test_runtime_timestamp_staleness_and_future_values_are_not_current():
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert runtime_evidence_freshness(now.isoformat(), now=now) == "CURRENT"
    assert runtime_evidence_freshness((now - timedelta(days=2)).isoformat(), now=now) == "STALE"
    assert runtime_evidence_freshness((now + timedelta(hours=1)).isoformat(), now=now) == "FUTURE"
    assert runtime_evidence_freshness("not-a-time", now=now) == "INVALID"


def test_runtime_input_validation_rejects_paths_and_sensitive_context(tmp_path):
    from types import ModuleType

    store = EvidenceStore()
    observer = RuntimeInstrumentation(store)
    for module_name, distribution, env in (
        ("../secrets", "demo", "local"),
        ("valid_module", "demo", "token=secret"),
    ):
        try:
            RuntimeInstrumentation(store, environment=env).observe_loaded_module(module_name, distribution)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed or sensitive runtime context must be rejected")
    fake = ModuleType("not_loaded")
    sys.modules.pop("not_loaded", None)
    assert observer.store.list() == []
    try:
        observer.observe_loaded_module("not_loaded", "demo")
    except ValueError:
        pass
    else:
        raise AssertionError("unloaded modules must not produce evidence")
