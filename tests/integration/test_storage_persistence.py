"""Checks the local SQLite adapter survives closing and reopening the process store."""

from guardianos.storage.sqlite import SQLiteDocumentStore


def test_sqlite_document_and_audit_records_survive_reopen(tmp_path):
    database = str(tmp_path / "osprey-state.sqlite3")
    first = SQLiteDocumentStore(database)
    first.put("components", "observation-1", {"purl": "pkg:pypi/demo@1.0.0"})
    first.append_audit_event({"id": "event-1", "action": "SBOM_INGESTED"})
    first.close()

    reopened = SQLiteDocumentStore(database)
    try:
        assert reopened.get("components", "observation-1") == {"purl": "pkg:pypi/demo@1.0.0"}
        assert reopened.recent_audit_events() == [{"action": "SBOM_INGESTED", "id": "event-1"}]
    finally:
        reopened.close()
