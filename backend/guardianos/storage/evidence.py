"""SQLite-backed evidence ledger for backend analysis runs."""

from __future__ import annotations

from osprey.core.evidence import EvidenceStore
from osprey.core.models import Evidence, EvidenceType

from guardianos.storage.sqlite import SQLiteDocumentStore, state_store


class PersistentEvidenceStore(EvidenceStore):
    def __init__(self, document_store: SQLiteDocumentStore | None = None) -> None:
        super().__init__()
        self.document_store = document_store or state_store
        for evidence_id, payload in self.document_store.list("evidence").items():
            try:
                if not isinstance(payload, dict):
                    continue
                record = Evidence(
                    id=payload.get("id", evidence_id),
                    type=EvidenceType(payload["type"]),
                    source=payload["source"],
                    location=payload["location"],
                    timestamp=payload["timestamp"],
                    confidence=float(payload["confidence"]),
                    content_hash=payload["content_hash"],
                    metadata=payload.get("metadata", {}),
                    content="",
                    record_hash=payload.get("record_hash", ""),
                )
            except (KeyError, TypeError, ValueError):
                continue
            self._records[evidence_id] = record

    def add(self, **kwargs):
        record = super().add(**kwargs)
        self.document_store.put("evidence", record.id, {
            "id": record.id,
            "type": record.type.value,
            "source": record.source,
            "location": record.location,
            "timestamp": record.timestamp,
            "confidence": record.confidence,
            "content_hash": record.content_hash,
            "metadata": record.metadata,
            "record_hash": record.record_hash,
        })
        return record

    def clear(self) -> None:
        super().clear()
        self.document_store.clear("evidence")


evidence_store = PersistentEvidenceStore()
