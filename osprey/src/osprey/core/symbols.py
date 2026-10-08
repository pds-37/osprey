"""Conservative normalization of advisory-provided vulnerable symbols."""

from __future__ import annotations

from typing import Any

from osprey.core.models import VulnerableSymbol


_ECOSYSTEM_ALIASES = {
    "node": "npm",
    "nodejs": "npm",
    "pypi": "pypi",
    "python": "pypi",
    "golang": "go",
    "go": "go",
    "crates.io": "cargo",
    "cargo": "cargo",
}


def _normalize_ecosystem(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "")
    return _ECOSYSTEM_ALIASES.get(normalized, normalized)


def _normalize_package(value: Any, ecosystem: str) -> str:
    normalized = str(value or "").strip().lower()
    if ecosystem == "pypi":
        normalized = normalized.replace("_", "-").replace(".", "-")
    return normalized


def extract_osv_vulnerable_symbols(
    advisory: dict[str, Any],
    *,
    package: str,
    ecosystem: str,
    vulnerability_id: str | None = None,
) -> list[VulnerableSymbol]:
    """Return only symbol strings scoped to this exact OSV affected package.

    OSV symbol extensions are not standardized. Osprey accepts string values
    under an affected record's ``ecosystem_specific`` or ``database_specific``
    object, and requires that record to name both package and ecosystem. Root
    ``database_specific`` values and unscoped affected records stay unknown.
    """
    wanted_ecosystem = _normalize_ecosystem(ecosystem)
    wanted_package = _normalize_package(package, wanted_ecosystem)
    if not wanted_ecosystem or not wanted_package:
        return []

    result: list[VulnerableSymbol] = []
    affected_records = extract_osv_affected_records(
        advisory, package=package, ecosystem=ecosystem
    )
    advisory_id = str(vulnerability_id or advisory.get("id") or "UNKNOWN")
    for index, affected in affected_records:
        for container_name in ("ecosystem_specific", "database_specific"):
            container = affected.get(container_name)
            if not isinstance(container, dict):
                continue
            values = container.get("symbols")
            if values is None:
                values = container.get("vulnerable_symbols")
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                # Structured or non-string values have no defined OSV schema;
                # do not guess which portion denotes a module or symbol.
                if not isinstance(value, str) or not value.strip():
                    continue
                result.append(
                    VulnerableSymbol(
                        ecosystem=wanted_ecosystem,
                        package=package,
                        symbol=value.strip(),
                        vulnerability_id=advisory_id,
                        source=f"OSV affected[{index}].{container_name}.symbols",
                    )
                )
    unique: dict[tuple[str, str, str], VulnerableSymbol] = {}
    for mapping in result:
        key = (mapping.ecosystem, mapping.package.lower(), mapping.symbol)
        unique.setdefault(key, mapping)
    return list(unique.values())


def extract_osv_affected_records(
    advisory: dict[str, Any],
    *,
    package: str,
    ecosystem: str,
) -> list[tuple[int, dict[str, Any]]]:
    """Return only OSV affected records naming the requested package/ecosystem."""
    wanted_ecosystem = _normalize_ecosystem(ecosystem)
    wanted_package = _normalize_package(package, wanted_ecosystem)
    affected_records = advisory.get("affected", [])
    if not wanted_ecosystem or not wanted_package or not isinstance(affected_records, list):
        return []

    matches: list[tuple[int, dict[str, Any]]] = []
    for index, affected in enumerate(affected_records):
        if not isinstance(affected, dict):
            continue
        package_record = affected.get("package")
        if not isinstance(package_record, dict):
            continue
        affected_ecosystem = _normalize_ecosystem(package_record.get("ecosystem"))
        affected_package = _normalize_package(package_record.get("name"), affected_ecosystem)
        if affected_ecosystem == wanted_ecosystem and affected_package == wanted_package:
            matches.append((index, affected))
    return matches
