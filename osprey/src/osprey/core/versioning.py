"""Conservative OSV affected-range evaluation with ecosystem-aware comparison."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any, Iterable

from packaging.version import InvalidVersion, Version

from osprey.core.models import VersionMatchStatus


@dataclass(frozen=True)
class VersionMatch:
    status: VersionMatchStatus
    reason: str


def _ecosystem_name(ecosystem: str | None) -> str:
    value = (ecosystem or "").strip().lower()
    if value.startswith("debian:"):
        return "debian"
    aliases = {
        "pypi": "pypi",
        "python": "pypi",
        "npm": "npm",
        "node": "npm",
        "golang": "go",
        "go": "go",
        "cargo": "cargo",
        "crates.io": "cargo",
        "debian": "debian",
        "deb": "debian",
    }
    return aliases.get(value, value)


def _compare_semver(left: str, right: str) -> int | None:
    pattern = re.compile(
        r"^[v=]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
    )

    def parse(value: str) -> tuple[tuple[int, int, int], tuple[str, ...]] | None:
        match = pattern.fullmatch(value.strip())
        if not match:
            return None
        pre = tuple(match.group(4).split(".")) if match.group(4) else ()
        if any(not item or (item.isdigit() and len(item) > 1 and item.startswith("0")) for item in pre):
            return None
        return (int(match.group(1)), int(match.group(2)), int(match.group(3))), pre

    a = parse(left)
    b = parse(right)
    if a is None or b is None:
        return None
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    apre, bpre = a[1], b[1]
    if not apre or not bpre:
        if apre == bpre:
            return 0
        return -1 if apre else 1
    for x, y in zip(apre, bpre):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return -1 if x < y else 1
    if len(apre) == len(bpre):
        return 0
    return -1 if len(apre) < len(bpre) else 1


def _debian_part_order(char: str | None) -> int:
    if char == "~":
        return -1
    if char is None:
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_debian_part(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a = left[i] if i < len(left) and not left[i].isdigit() else None
            b = right[j] if j < len(right) and not right[j].isdigit() else None
            oa, ob = _debian_part_order(a), _debian_part_order(b)
            if oa != ob:
                return -1 if oa < ob else 1
            if a is not None:
                i += 1
            if b is not None:
                j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        i0, j0 = i, j
        while i < len(left) and left[i].isdigit():
            i += 1
        while j < len(right) and right[j].isdigit():
            j += 1
        la, lb = i - i0, j - j0
        if la != lb:
            return -1 if la < lb else 1
        if left[i0:i] != right[j0:j]:
            return -1 if left[i0:i] < right[j0:j] else 1
    return 0


def _compare_debian(left: str, right: str) -> int | None:
    def parse(value: str) -> tuple[int, str, str] | None:
        value = value.strip()
        match = re.fullmatch(r"(?:(\d+):)?([0-9A-Za-z.+:~\-]+)", value)
        if not match:
            return None
        epoch = int(match.group(1) or 0)
        upstream_revision = match.group(2)
        if "-" in upstream_revision:
            upstream, revision = upstream_revision.rsplit("-", 1)
        else:
            upstream, revision = upstream_revision, "0"
        return epoch, upstream, revision

    a, b = parse(left), parse(right)
    if a is None or b is None:
        return None
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    upstream_cmp = _compare_debian_part(a[1], b[1])
    return upstream_cmp if upstream_cmp else _compare_debian_part(a[2], b[2])


def compare_versions(left: str, right: str, ecosystem: str | None = None) -> int | None:
    """Compare two versions; return None when the ecosystem/version syntax is unsupported."""
    kind = _ecosystem_name(ecosystem)
    if kind in {"pypi"}:
        try:
            a, b = Version(left.strip()), Version(right.strip())
        except (InvalidVersion, AttributeError):
            return None
        return (a > b) - (a < b)
    if kind in {"npm", "go", "cargo"}:
        return _compare_semver(left, right)
    if kind == "debian":
        return _compare_debian(left, right)
    return None


def _evaluate_range_events(installed: str, ecosystem: str, range_record: dict[str, Any]) -> VersionMatch:
    events = range_record.get("events")
    if not isinstance(events, list) or not events:
        return VersionMatch(VersionMatchStatus.UNKNOWN, "affected range has no OSV events")
    active = False
    start: str | None = None
    start_is_unbounded = False
    known_result = False
    unknown_result = False

    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            unknown_result = True
            continue
        kind, raw_boundary = next(iter(event.items()))
        boundary = str(raw_boundary).strip()
        if kind == "introduced":
            if active:
                unknown_result = True
            active = True
            start_is_unbounded = boundary == "0"
            start = None if start_is_unbounded else boundary
            if not start_is_unbounded and compare_versions(installed, boundary, ecosystem) is None:
                unknown_result = True
            continue

        if kind not in {"fixed", "last_affected", "limit"}:
            unknown_result = True
            continue
        if not active:
            # A fixed event without an explicit introduced event is not proof that
            # every earlier version was affected.
            unknown_result = True
            continue
        upper_cmp = compare_versions(installed, boundary, ecosystem)
        lower_cmp = 1 if start_is_unbounded else (compare_versions(installed, start or "", ecosystem))
        if upper_cmp is None or lower_cmp is None:
            unknown_result = True
        else:
            lower_ok = start_is_unbounded or lower_cmp >= 0
            upper_ok = upper_cmp <= 0 if kind == "last_affected" else upper_cmp < 0
            known_result = True
            if lower_ok and upper_ok:
                return VersionMatch(VersionMatchStatus.AFFECTED, f"version is inside an OSV {kind} range")
        active = False
        start = None
        start_is_unbounded = False

    if active:
        lower_cmp = 1 if start_is_unbounded else compare_versions(installed, start or "", ecosystem)
        if lower_cmp is None:
            unknown_result = True
        else:
            known_result = True
            if start_is_unbounded or lower_cmp >= 0:
                return VersionMatch(VersionMatchStatus.AFFECTED, "version is inside an open OSV range")
    if unknown_result:
        return VersionMatch(VersionMatchStatus.UNKNOWN, "one or more affected ranges have missing or unsupported boundaries")
    if known_result:
        return VersionMatch(VersionMatchStatus.NOT_AFFECTED, "version is outside the declared OSV ranges")
    return VersionMatch(VersionMatchStatus.UNKNOWN, "no complete affected range was supplied")


def evaluate_version(
    installed: str,
    ecosystem: str,
    *,
    ranges: Iterable[dict[str, Any]] = (),
    exact_versions: Iterable[str] = (),
    fixed_versions: Iterable[str] = (),
    introduced_versions: Iterable[str] = (),
) -> VersionMatch:
    """Evaluate OSV-style ranges and exact versions without inventing a lower bound."""
    installed = (installed or "").strip()
    if not installed or installed.lower() in {"unknown", "*"}:
        return VersionMatch(VersionMatchStatus.UNKNOWN, "installed version is missing")

    exacts = [str(value).strip() for value in exact_versions if str(value).strip()]
    for exact in exacts:
        comparison = compare_versions(installed, exact, ecosystem)
        if comparison == 0:
            return VersionMatch(VersionMatchStatus.AFFECTED, f"installed version exactly matches {exact}")

    range_list = list(ranges)
    if range_list:
        results = [_evaluate_range_events(installed, ecosystem, item) for item in range_list]
        for result in results:
            if result.status == VersionMatchStatus.AFFECTED:
                return result
        if any(result.status == VersionMatchStatus.UNKNOWN for result in results):
            return VersionMatch(VersionMatchStatus.UNKNOWN, "no affected range matched and at least one range is incomplete")
        return VersionMatch(VersionMatchStatus.NOT_AFFECTED, "version is outside all declared OSV ranges")

    intros = [str(value).strip() for value in introduced_versions if str(value).strip()]
    fixed = [str(value).strip() for value in fixed_versions if str(value).strip()]
    if intros and fixed and len(intros) == len(fixed):
        synthetic = [
            {"events": [{"introduced": lo}, {"fixed": hi}]}
            for lo, hi in zip(intros, fixed)
        ]
        return evaluate_version(installed, ecosystem, ranges=synthetic, exact_versions=exacts)

    if exacts:
        comparisons = [compare_versions(installed, exact, ecosystem) for exact in exacts]
        if all(value is not None for value in comparisons):
            return VersionMatch(VersionMatchStatus.NOT_AFFECTED, "version is not in the advisory exact-version list")
        return VersionMatch(VersionMatchStatus.UNKNOWN, "one or more exact advisory versions cannot be compared for this ecosystem")

    if fixed or intros:
        return VersionMatch(VersionMatchStatus.UNKNOWN, "fixed or introduced versions lack a complete paired range")
    return VersionMatch(VersionMatchStatus.UNKNOWN, "advisory contains no usable affected-version boundaries")


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
    """Compatibility helper: return True only for a positively affected version."""
    structured = list(ranges)
    if structured:
        result = evaluate_version(installed, ecosystem, ranges=structured, exact_versions=exact_versions)
        return result.status == VersionMatchStatus.AFFECTED
    if affected_ranges:
        # Legacy strings do not carry a lower-bound event. In particular, a bare
        # '< fixed' must not be widened to all historical versions.
        for rule in affected_ranges:
            match = re.fullmatch(r"\s*(==|=)\s*(\S+)\s*", rule)
            if match and compare_versions(installed, match.group(2), ecosystem) == 0:
                return True
    result = evaluate_version(
        installed,
        ecosystem,
        fixed_versions=fixed_versions or (),
        introduced_versions=introduced_versions,
        exact_versions=exact_versions,
    )
    return result.status == VersionMatchStatus.AFFECTED
