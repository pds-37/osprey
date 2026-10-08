"""Deterministic evidence creation and lookup."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
import math
from typing import Any

from osprey.core.models import Evidence, EvidenceType


MAX_CONTENT_BYTES = 10_485_760
MAX_METADATA_BYTES = 65_536
MAX_SOURCE_LENGTH = 256
MAX_LOCATION_LENGTH = 2_048
EVIDENCE_SCHEMA_VERSION = 1


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible evidence values with stable, strict encoding."""
    def validate(item: Any) -> None:
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("non-finite numbers are not valid evidence values")
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                validate(child)
            return
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("evidence object keys must be strings")
            for child in item.values():
                validate(child)
            return
        raise ValueError("evidence values must contain only JSON-compatible data")

    try:
        validate(value)
    except RecursionError as exc:
        raise ValueError("evidence values exceed the supported nesting depth") from exc
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("evidence values must contain only finite JSON-compatible data") from exc


def content_digest(content: str | bytes) -> str:
    """Return SHA-256 over the exact UTF-8 text or bytes observed by the analyzer."""
    if isinstance(content, str):
        raw = content.encode("utf-8", "strict")
    elif isinstance(content, bytes):
        raw = content
    else:
        raise ValueError("evidence content must be text or bytes")
    if len(raw) > MAX_CONTENT_BYTES:
        raise ValueError("evidence content exceeds the configured size limit")
    return hashlib.sha256(raw).hexdigest()


def _identity_payload(
    evidence_type: EvidenceType,
    source: str,
    location: str,
    digest: str,
    confidence: float,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": evidence_type.value,
        "source": source,
        "location": location,
        "content_hash": digest,
        "confidence": confidence,
        "metadata": metadata,
    }


def _evidence_id(payload: dict[str, Any]) -> str:
    return "ev-" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:24]


def _record_hash(record: Evidence) -> str:
    payload = {
        "id": record.id,
        "type": record.type.value,
        "source": record.source,
        "location": record.location,
        "timestamp": record.timestamp,
        "confidence": record.confidence,
        "content_hash": record.content_hash,
        "metadata": record.metadata,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def verify_record(record: Evidence) -> bool | None:
    """Verify the stored envelope and content-derived ID; None marks a legacy record."""
    if not record.record_hash:
        return None
    try:
        identity = _identity_payload(
            record.type,
            record.source,
            record.location,
            record.content_hash,
            record.confidence,
            record.metadata,
        )
        id_matches = hmac.compare_digest(record.id, _evidence_id(identity))
        hash_matches = hmac.compare_digest(record.record_hash, _record_hash(record))
        return id_matches and hash_matches
    except (AttributeError, TypeError, ValueError):
        return False


class EvidenceStore:
    """In-process evidence ledger. Persistence is supplied by an adapter."""

    def __init__(self) -> None:
        self._records: dict[str, Evidence] = {}

    def add(
        self,
        *,
        evidence_type: EvidenceType,
        source: str,
        location: str,
        content: str | bytes | None = None,
        content_hash: str | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not isinstance(evidence_type, EvidenceType):
            raise ValueError("evidence_type must be a supported EvidenceType")
        for label, value, maximum in (
            ("source", source, MAX_SOURCE_LENGTH),
            ("location", location, MAX_LOCATION_LENGTH),
        ):
            if not isinstance(value, str) or not value or len(value) > maximum or any(ord(ch) < 32 for ch in value):
                raise ValueError(f"evidence {label} is invalid or exceeds the configured size limit")

        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("evidence metadata must be a JSON object")
        metadata_json = canonical_json(metadata)
        if len(metadata_json.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("evidence metadata exceeds the configured size limit")
        clean_metadata = json.loads(metadata_json)
        clean_metadata["evidence_schema_version"] = EVIDENCE_SCHEMA_VERSION
        metadata_json = canonical_json(clean_metadata)
        if len(metadata_json.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("evidence metadata exceeds the configured size limit")

        observed_content = "" if content is None else content
        calculated_digest = content_digest(observed_content)
        if content_hash is None:
            digest = calculated_digest
        else:
            if not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", content_hash):
                raise ValueError("content_hash must be a 64-character SHA-256 hex digest")
            digest = content_hash.lower()
            if content is not None and not hmac.compare_digest(digest, calculated_digest):
                raise ValueError("content_hash does not match the supplied evidence content")

        confidence_value = float(confidence)
        identity = _identity_payload(
            evidence_type, source, location, digest, confidence_value, clean_metadata
        )
        evidence_id = _evidence_id(identity)
        record = self._records.get(evidence_id)
        if record is None:
            record = Evidence(
                id=evidence_id,
                type=evidence_type,
                source=source,
                location=location,
                timestamp=datetime.now(timezone.utc).isoformat(),
                confidence=confidence_value,
                content_hash=digest,
                # Keep source/advisory contents out of the evidence ledger by default.
                content="",
                metadata=clean_metadata,
            )
            record = replace(record, record_hash=_record_hash(record))
            self._records[evidence_id] = record
        return record

    def get(self, evidence_id: str) -> Evidence | None:
        return self._records.get(evidence_id)

    def list(self) -> list[Evidence]:
        return list(self._records.values())

    def verify_record(self, record_or_id: Evidence | str) -> bool | None:
        record = self.get(record_or_id) if isinstance(record_or_id, str) else record_or_id
        return verify_record(record) if record is not None else False

    def verify_content(self, record_or_id: Evidence | str, content: str | bytes) -> bool:
        """Compare observed content with its evidence hash without retaining raw content."""
        record = self.get(record_or_id) if isinstance(record_or_id, str) else record_or_id
        if record is None:
            return False
        try:
            return hmac.compare_digest(record.content_hash, content_digest(content))
        except ValueError:
            return False

    def integrity_status(self, record: Evidence) -> str:
        verified = verify_record(record)
        return "UNVERIFIED_LEGACY" if verified is None else "VERIFIED" if verified else "MISMATCH"

    def clear(self) -> None:
        self._records.clear()


evidence_store = EvidenceStore()
