"""Inference engine for package-level network and runtime exposure.

EXPOSURE RULES:
- dev-only: package only in devDependencies / dev groups -> 'dev-only'
- HTTP route/listener declaration -> entrypoint observed; external reachability remains unknown
- Dockerfile EXPOSE / Compose host-port mapping -> port declared; Internet reachability remains unknown
- no Compose port mapping -> ingress remains unknown (other routing may exist)
- otherwise -> 'unknown'
- osprey.yaml may override per service or package with confidence 'declared'.
- Stores: level, confidence ('declared' | 'inferred' | 'unknown'), evidence (file path + reason).

Assumptions and Limitations:
- Evaluates package-level exposure based on manifest scope and service entrypoints.
- Function-level reachability is evaluated separately by the reachability analyzer.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from osprey.models import Component, ExposureInfo, Service
from osprey.filesystem import walk_workspace

IGNORE_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".cache",
    "target",
}


def scan_source_code_listeners(root_dir: Path) -> List[ExposureInfo]:
    """Return static route/listener observations without asserting public reachability."""
    if not root_dir.exists():
        return []

    import os
    from osprey.analyzers.source import analyze_source_files

    files: dict[str, str] = {}
    total_bytes = 0
    root = root_dir.resolve()
    for current_dir, _dirs, names, _skipped in walk_workspace(
        root, skip_dirs=IGNORE_DIRS, max_depth=4
    ):
        for name in names:
            file_path = current_dir / name
            if file_path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".py", ".go"} or file_path.is_symlink():
                continue
            try:
                resolved = file_path.resolve()
                relative = resolved.relative_to(root).as_posix()
                size = resolved.stat().st_size
                if size > 1_000_000 or len(files) >= 500 or total_bytes + size > 10_000_000:
                    continue
                files[relative] = resolved.read_text(encoding="utf-8", errors="replace")
                total_bytes += size
            except (OSError, ValueError):
                continue

    analysis = analyze_source_files(files, [])
    return [
        ExposureInfo(
            level="unknown",
            confidence="inferred",
            evidence=f"Static {item.framework} route/listener {item.method} {item.route} observed at {item.file}:{item.line}; external routing and authentication are not observed",
        )
        for item in analysis.exposures
    ]


def map_component_to_service(
    component: Component,
    services: List[Service],
    root_path: Optional[Path] = None,
) -> Optional[Service]:
    """Map a component to the service that owns its manifest file.

    Mapping criteria:
    1. Direct Dockerfile COPY/ADD path match:
       If a service's Dockerfile explicitly copies this manifest filename or path.
    2. Build context containment:
       If the manifest file is located inside the service's build context directory.
       When multiple services match, pick the most specific (longest path) build context.
    3. If multiple services share the same build context and neither explicitly copies the file,
       the mapping cannot be proven -> return None.
    """
    if not services or not component.source_file:
        return None

    manifest_path = Path(component.source_file).resolve()
    manifest_name = manifest_path.name.lower()

    # 1. First check explicit Dockerfile COPY / ADD match
    copy_matched_services: List[Service] = []
    for svc in services:
        if svc.copied_files:
            for copied in svc.copied_files:
                if manifest_name == Path(copied).name.lower() or str(manifest_path).lower().endswith(copied.lower()):
                    copy_matched_services.append(svc)
                    break

    if len(copy_matched_services) == 1:
        return copy_matched_services[0]

    # 2. Check build context containment
    matching_services: List[tuple[int, Service]] = []
    for svc in services:
        if svc.build_context:
            ctx_path = Path(svc.build_context).resolve()
            try:
                manifest_path.relative_to(ctx_path)
                matching_services.append((len(str(ctx_path)), svc))
            except ValueError:
                pass

    if not matching_services:
        return None

    # Sort by path length descending (most specific context first)
    matching_services.sort(key=lambda x: x[0], reverse=True)

    if len(matching_services) == 1:
        return matching_services[0][1]

    top_len, top_svc = matching_services[0]
    second_len, _ = matching_services[1]

    if top_len > second_len:
        return top_svc

    # Ambiguous: cannot be proven
    return None


def evaluate_exposure(
    component: Component,
    service: Optional[Service] = None,
    ambient_exposures: Optional[List[ExposureInfo]] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> ExposureInfo:
    """Determine the package-level exposure for a component adhering strictly to Osprey rules."""
    overrides = overrides or {}
    ambient_exposures = ambient_exposures or []

    # 1. Declared override for component in osprey.yaml
    pkg_overrides = overrides.get("packages", {})
    if component.name.lower() in pkg_overrides:
        decl = pkg_overrides[component.name.lower()]
        level = decl.get("exposure", "unknown")
        reason = decl.get("reason", "configured in osprey.yaml")
        return ExposureInfo(
            level=level,
            confidence="declared",
            evidence=f"osprey.yaml package override ({reason})",
        )

    # 2. Declared override for parent service in osprey.yaml
    svc_overrides = overrides.get("services", {})
    if service and service.name.lower() in svc_overrides:
        decl = svc_overrides[service.name.lower()]
        level = decl.get("exposure", "unknown")
        reason = decl.get("reason", "configured in osprey.yaml")
        return ExposureInfo(
            level=level,
            confidence="declared",
            evidence=f"osprey.yaml service override '{service.name}' ({reason})",
        )

    # 3. Dev-only rule: package only in devDependencies / dev groups
    if component.is_dev:
        source_name = Path(component.source_file).name if component.source_file else "manifest"
        return ExposureInfo(
            level="dev-only",
            confidence="inferred",
            evidence=f"{source_name} (dev-only dependency)",
        )

    # 4. Service metadata is only as reliable as the supplied evidence. A
    # port declaration does not prove public network reachability.
    if service and service.exposure:
        return service.exposure

    # 5. Static route declarations establish entrypoints, not internet routing.
    if not service and ambient_exposures:
        return ExposureInfo(
            level="unknown",
            confidence="inferred",
            evidence="HTTP route/listener declaration observed; external routing and authentication are not observed",
        )

    # 6. Default fallback: If mapping cannot be proven, exposure must be "unknown", NEVER "public".
    return ExposureInfo(
        level="unknown",
        confidence="unknown",
        evidence="unmapped service or unproven exposure boundary",
    )
