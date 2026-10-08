"""Compatibility adapter for the shared ecosystem-aware version evaluator."""

from __future__ import annotations

from typing import Any, Iterable

from osprey.core.versioning import (
    VersionMatch,
    VersionMatchStatus,
    compare_versions as _compare_versions,
    evaluate_version,
    is_version_affected as _is_version_affected,
)


def compare_versions(v1: str, v2: str, ecosystem: str = "debian") -> int | None:
    """Compare using the supplied ecosystem (Debian is the legacy default)."""
    return _compare_versions(v1, v2, ecosystem)


def is_version_affected(
    installed: str,
    affected_ranges: list[str] | None = None,
    fixed_versions: list[str] | None = None,
    *,
    ecosystem: str = "",
    ranges: Iterable[dict[str, Any]] = (),
    exact_versions: Iterable[str] = (),
    introduced_versions: Iterable[str] = (),
) -> bool:
    """Return true only when supplied advisory boundaries positively match."""
    return _is_version_affected(
        installed,
        affected_ranges,
        fixed_versions,
        ecosystem=ecosystem,
        ranges=ranges,
        exact_versions=exact_versions,
        introduced_versions=introduced_versions,
    )


__all__ = ["VersionMatch", "VersionMatchStatus", "compare_versions", "evaluate_version", "is_version_affected"]
