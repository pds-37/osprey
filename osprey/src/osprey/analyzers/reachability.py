"""Conservative reachability decisions from static source evidence."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from osprey.analyzers.source import SourceAnalysis, _canonical_package
from osprey.core.models import ReachabilityEdge, ReachabilityResult, ReachabilityStatus, VulnerableSymbol


REACHABILITY_LIMITATIONS = (
    "Static analysis covers only supported syntax in files included in this scan.",
    "Dynamic imports, reflection, generated code, and runtime-loaded behavior are not resolved.",
    "A detected source route does not establish Internet exposure, authentication state, or exploitability.",
    "Internal call edges are inferred from supported syntax and are not separately recorded as callsite evidence.",
)


def _limitations_for(analysis: SourceAnalysis) -> tuple[str, ...]:
    limitations = list(REACHABILITY_LIMITATIONS)
    if analysis.errors:
        limitations.append("Analysis was incomplete: " + "; ".join(analysis.errors[:3]))
    if analysis.traversal_truncated:
        limitations.append(
            f"Call graph traversal was truncated at the configured {analysis.max_graph_depth}-edge depth limit."
        )
    return tuple(dict.fromkeys(limitations))


def _symbol_value(value: Any, package: str, ecosystem: str | None) -> tuple[str, float, str] | None:
    if isinstance(value, str):
        symbol = value.strip().lstrip(".")
        return (symbol, 0.8, "advisory symbol") if symbol else None

    if isinstance(value, VulnerableSymbol):
        mapping_package = value.package
        symbol = value.symbol
        module_path = value.module_path
        confidence = value.confidence
        source = value.source
        mapping_ecosystem = value.ecosystem
    elif isinstance(value, Mapping):
        mapping_package = str(value.get("package", ""))
        symbol = str(value.get("symbol", ""))
        module_path = value.get("module_path")
        confidence = value.get("confidence", 0.0)
        source = str(value.get("source", "advisory symbol"))
        mapping_ecosystem = str(value.get("ecosystem", ""))
    else:
        return None

    if not mapping_package or _canonical_package(mapping_package) != _canonical_package(package):
        return None
    if ecosystem and mapping_ecosystem and _ecosystem_key(mapping_ecosystem) != _ecosystem_key(ecosystem):
        return None
    symbol = symbol.strip().lstrip(".")
    module = str(module_path or "").strip().strip(".")
    if module:
        symbol = f"{module}.{symbol}" if symbol else module
    try:
        confidence_value = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence_value = 0.0
    return (symbol, confidence_value, source) if symbol else None


def _ecosystem_key(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "")
    return {
        "node": "npm",
        "nodejs": "npm",
        "python": "pypi",
        "golang": "go",
        "crates.io": "cargo",
    }.get(normalized, normalized)


def _mapping_limitations(values: Sequence[Any], ecosystem: str | None) -> tuple[str, ...]:
    limitations: list[str] = []
    for value in values:
        if isinstance(value, VulnerableSymbol):
            candidate_ecosystem = value.ecosystem
            items = value.limitations
        elif isinstance(value, Mapping):
            candidate_ecosystem = str(value.get("ecosystem", ""))
            items = value.get("limitations", ())
        else:
            continue
        if ecosystem and candidate_ecosystem and _ecosystem_key(candidate_ecosystem) != _ecosystem_key(ecosystem):
            continue
        if isinstance(items, str):
            items = [items]
        if isinstance(items, (list, tuple)):
            limitations.extend(str(item) for item in items if str(item).strip())
    return tuple(dict.fromkeys(limitations))


def _strip_package_prefix(symbol: str, package: str) -> str:
    value = symbol.strip().lstrip(".")
    package_prefix = package.strip().rstrip("/")
    for separator in (".", "/"):
        prefix = package_prefix + separator
        if value.lower().startswith(prefix.lower()):
            return value[len(prefix):]
    return value


def _symbol_matches(observed: str, vulnerable: str, package: str) -> bool:
    """Match exact symbols or an advisory's unqualified function name.

    A qualified advisory symbol is never reduced to a leaf unless its explicit
    package prefix can be removed. This prevents ``safe`` from matching an
    unrelated ``other.module.safe`` advisory symbol.
    """
    left = _strip_package_prefix(observed, package)
    right = _strip_package_prefix(vulnerable, package)
    if not left or not right:
        return False
    if left == right:
        return True
    return "." not in right and left.endswith("." + right)


def analyze_reachability(
    analysis: SourceAnalysis,
    *,
    package: str,
    vulnerable_symbols: Sequence[str | VulnerableSymbol | Mapping[str, Any]],
    direct_dependency: bool = False,
    ecosystem: str | None = None,
    symbol_evidence_ids: Sequence[str] = (),
) -> ReachabilityResult:
    """Determine whether a named vulnerable dependency symbol is route-reachable.

    A package advisory without vulnerable-symbol metadata is deliberately UNKNOWN.
    A negative result is limited to the supplied source files and parser subset.
    """
    package_key = _canonical_package(package)
    evidence_ids = {item for item in analysis.file_evidence.values()}
    evidence_ids.update(
        exposure.evidence_id for exposure in analysis.exposures if exposure.evidence_id
    )
    evidence_ids.update(item for item in symbol_evidence_ids if item)
    limitations = tuple(dict.fromkeys((
        *_limitations_for(analysis),
        *_mapping_limitations(vulnerable_symbols, ecosystem),
    )))
    package_usages = [
        usage for usage in analysis.usages
        if _canonical_package(usage.package) == package_key
    ]
    evidence_ids.update(usage.evidence_id for usage in package_usages if usage.evidence_id)

    normalized_symbols = [
        value for item in vulnerable_symbols
        if (value := _symbol_value(item, package, ecosystem)) is not None
    ]
    symbols = [value[0] for value in normalized_symbols]
    if not symbols:
        mismatch = bool(vulnerable_symbols)
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason=(
                "The advisory symbol mapping is not scoped to this package."
                if mismatch
                else "The advisory does not identify a vulnerable function or symbol."
            ),
            limitations=limitations,
        )

    call_usages = [
        usage for usage in package_usages
        if usage.usage_type == "CALL"
        and any(_symbol_matches(usage.symbol, symbol, package) for symbol in symbols)
    ]

    # The shared analyzer builds this bounded route closure once per workspace
    # analysis. Findings reuse its parent map instead of traversing all files
    # independently for every advisory.
    parents = analysis.route_parents

    for usage in call_usages:
        matched_mappings = [
            item for item in normalized_symbols
            if _symbol_matches(usage.symbol, item[0], package)
        ]
        caller = usage.caller
        if caller and caller in parents:
            chain: list[str] = []
            cursor: str | None = caller
            while cursor is not None:
                chain.append(cursor)
                cursor = parents.get(cursor)
            chain.reverse()
            route_root = chain[0] if chain else ""
            route = next((item for item in analysis.exposures if item.handler == route_root), None)
            path_files = {usage.file}
            path_files.update(
                analysis.functions[item].file for item in chain if item in analysis.functions
            )
            if route:
                path_files.add(route.file)
            parse_markers = (
                "syntax recovery",
                "syntax could not be parsed",
                "parser timed out",
                "parser dependencies are unavailable",
            )
            path_parse_errors = [
                error for error in analysis.errors
                if any(error.startswith(f"{path}:") for path in path_files)
                and any(marker in error.lower() for marker in parse_markers)
            ]
            if path_parse_errors:
                limitations = tuple(dict.fromkeys((
                    *limitations,
                    "A source file on the candidate route-to-symbol path required parser recovery; reachability is UNKNOWN.",
                )))
                return ReachabilityResult(
                    ReachabilityStatus.UNKNOWN,
                    0.0,
                    evidence=tuple(sorted(evidence_ids)),
                    reason="A candidate route-to-symbol path crosses source with syntax recovery and cannot be established safely.",
                    limitations=limitations,
                )
            origin = analysis.route_origins.get(caller, "Observed route")
            function_path = tuple(
                analysis.functions[item].display if item in analysis.functions else item
                for item in chain
            )
            path = (origin, *function_path, f"{package}.{usage.symbol}")
            path_edges: list[ReachabilityEdge] = []
            route_handler = analysis.functions.get(route_root)
            if route and route_handler:
                path_edges.append(ReachabilityEdge(
                    source_file=route.file,
                    source_symbol=f"{route.method} {route.route}",
                    target_file=route_handler.file,
                    target_symbol=route_handler.name,
                    relation="route_handler",
                    resolution="static route handler identified",
                    confidence=route.confidence,
                    line=route.line,
                    evidence_id=route.evidence_id,
                ))
            for child in chain[1:]:
                edge = analysis.route_parent_edges.get(child)
                if edge:
                    path_edges.append(ReachabilityEdge(
                        source_file=edge.source_file,
                        source_symbol=edge.source_symbol,
                        target_file=edge.target_file,
                        target_symbol=edge.target_symbol,
                        relation="static_call",
                        resolution=edge.resolution,
                        confidence=edge.confidence,
                        line=edge.line,
                    ))
            source_function = analysis.functions.get(caller)
            path_edges.append(ReachabilityEdge(
                source_file=source_function.file if source_function else usage.file,
                source_symbol=source_function.name if source_function else "module scope",
                target_file=None,
                target_symbol=f"{package}.{usage.symbol}",
                relation="vulnerable_symbol_call",
                resolution="advisory-mapped symbol call observed",
                confidence=min(usage.confidence, *(item[1] for item in matched_mappings)),
                line=usage.line,
                evidence_id=usage.evidence_id,
            ))
            ids = set(evidence_ids)
            if usage.evidence_id:
                ids.add(usage.evidence_id)
            if route and route.evidence_id:
                ids.add(route.evidence_id)
            ids.update(analysis.function_evidence[item] for item in chain if item in analysis.function_evidence)
            path_confidences = [route.confidence] if route else []
            path_confidences.extend(
                edge.confidence
                for child in chain[1:]
                if (edge := analysis.route_parent_edges.get(child)) is not None
            )
            return ReachabilityResult(
                ReachabilityStatus.REACHABLE,
                min(0.9, usage.confidence, *(item[1] for item in matched_mappings), *path_confidences),
                path=tuple(path),
                evidence=tuple(sorted(ids)),
                reason=(
                    "A statically observed HTTP handler reaches a call to the "
                    f"advisory-mapped symbol {usage.symbol!r}. Mapping source: "
                    f"{', '.join(dict.fromkeys(item[2] for item in matched_mappings))}."
                ),
                limitations=limitations,
                path_edges=tuple(path_edges),
            )

    if analysis.errors:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason="Static analysis had unsupported syntax or incomplete files: " + "; ".join(analysis.errors[:3]),
            limitations=limitations,
        )

    if not analysis.files_scanned:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason="No supported source files were analyzed.",
            limitations=limitations,
        )

    if not analysis.exposures:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason="No supported HTTP entrypoint was observed.",
            limitations=limitations,
        )

    # If the symbol is called in the source but no supported route reaches it, we
    # can only rule out route reachability within this static subset.
    if call_usages:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason="A call to the vulnerable symbol was observed, but no supported path from an HTTP handler was established. Background, cross-file, and dynamic flows may be present.",
            limitations=limitations,
        )

    if analysis.traversal_truncated:
        return ReachabilityResult(
            ReachabilityStatus.UNKNOWN,
            0.0,
            evidence=tuple(sorted(evidence_ids)),
            reason=f"Route-to-function traversal reached the configured {analysis.max_graph_depth}-edge limit.",
            limitations=tuple(dict.fromkeys((*limitations, "Call graph traversal was truncated at its configured depth limit."))),
        )

    if package_usages:
        return ReachabilityResult(
            ReachabilityStatus.NOT_REACHABLE,
            0.65,
            evidence=tuple(sorted(evidence_ids)),
            reason=(
                "The dependency is imported or used, but no supported call to "
                f"the advisory-mapped symbol(s) {', '.join(symbols)} was observed "
                "from the exposed handlers."
            ),
            limitations=limitations,
        )

    return ReachabilityResult(
        ReachabilityStatus.UNKNOWN,
        0.0,
        evidence=tuple(sorted(evidence_ids)),
        reason="No source import or call for this dependency was observed; transitive or dynamic use cannot be ruled out.",
        limitations=limitations,
    )
