"""Parser for Node.js npm manifests (package.json and package-lock.json v2/v3).

Assumptions and Limitations:
- Reads package.json and package-lock.json strictly as UTF-8 JSON text.
- Accurately tags devDependencies as is_dev=True.
- In package-lock.json (v2/v3), top-level packages in node_modules/ are parsed with exact resolved versions.
"""

from __future__ import annotations

import json
from itertools import islice
from pathlib import Path
from typing import Dict, List

from osprey.models import Component
from osprey.parsers.base import (
    MAX_MANIFEST_COMPONENTS,
    MAX_MANIFEST_BYTES,
    clean_version,
    make_purl,
    read_bounded_text,
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


class NpmParser:
    """Parser for npm package.json and package-lock.json files."""

    name: str = "npm"

    def __init__(self) -> None:
        self.last_error: str | None = None

    def detect(self, path: Path) -> bool:
        return path.name in ("package.json", "package-lock.json")

    def parse(self, path: Path) -> List[Component]:
        self.last_error = None
        try:
            content = read_bounded_text(path, max_bytes=MAX_MANIFEST_BYTES)
            data = json.loads(content, object_pairs_hook=_unique_object)
        except Exception:
            self.last_error = "npm manifest could not be read or parsed"
            return []

        if not isinstance(data, dict):
            self.last_error = "npm manifest has an invalid top-level shape"
            return []

        try:
            if path.name == "package-lock.json":
                if ("packages" in data and not isinstance(data["packages"], dict)
                        or "dependencies" in data and not isinstance(data["dependencies"], dict)):
                    self.last_error = "npm lockfile has an invalid dependency section"
                    return []
                return self._parse_lockfile(data, path)
            dependency_sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
            if any(key in data and not isinstance(data[key], dict) for key in dependency_sections):
                self.last_error = "npm manifest has an invalid dependency section"
                return []
            return self._parse_package_json(data, path)
        except Exception:
            self.last_error = "npm manifest contains unsupported dependency metadata"
            return []

    def _parse_package_json(self, data: dict, path: Path) -> List[Component]:
        components: List[Component] = []
        prod_deps: Dict[str, str] = data.get("dependencies", {}) or {}
        peer_deps: Dict[str, str] = data.get("peerDependencies", {}) or {}
        optional_deps: Dict[str, str] = data.get("optionalDependencies", {}) or {}
        dev_deps: Dict[str, str] = data.get("devDependencies", {}) or {}

        # 1. Regular declared dependencies (not proof of installed/runtime state)
        all_prod = {**prod_deps, **peer_deps, **optional_deps}
        for name, ver in islice(all_prod.items(), MAX_MANIFEST_COMPONENTS):
            if not isinstance(name, str) or len(name) > 512 or not isinstance(ver, str) or len(ver) > 512:
                continue
            c_ver = clean_version(ver)
            components.append(
                Component(
                    name=name,
                    version=c_ver,
                    ecosystem="npm",
                    purl=make_purl("npm", name, c_ver),
                    is_dev=False,
                    source_file=str(path),
                )
            )

        # 2. Development-only dependencies
        for name, ver in islice(dev_deps.items(), MAX_MANIFEST_COMPONENTS - len(components)):
            if not isinstance(name, str) or len(name) > 512 or not isinstance(ver, str) or len(ver) > 512:
                continue
            if name in all_prod:
                continue  # already counted among regular declared dependencies
            c_ver = clean_version(ver)
            components.append(
                Component(
                    name=name,
                    version=c_ver,
                    ecosystem="npm",
                    purl=make_purl("npm", name, c_ver),
                    is_dev=True,
                    source_file=str(path),
                )
            )

        return components

    def _parse_lockfile(self, data: dict, path: Path) -> List[Component]:
        components: List[Component] = []

        # v2 and v3 format: packages dict

        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_path, meta in islice(packages.items(), MAX_MANIFEST_COMPONENTS):
                if not isinstance(pkg_path, str) or len(pkg_path) > 4_096:
                    continue
                if not pkg_path or pkg_path == "" or not isinstance(meta, dict):
                    continue
                # Extract clean package name from node_modules/foo or node_modules/@scope/foo
                if "node_modules/" in pkg_path:
                    parts = pkg_path.split("node_modules/")
                    pkg_name = parts[-1]
                else:
                    pkg_name = pkg_path

                ver = meta.get("version")
                if not ver or not isinstance(ver, str) or len(ver) > 512:
                    continue
                c_ver = clean_version(ver)
                is_dev = bool(meta.get("dev", False))

                components.append(
                    Component(
                        name=pkg_name,
                        version=c_ver,
                        ecosystem="npm",
                        purl=make_purl("npm", pkg_name, c_ver),
                        is_dev=is_dev,
                        source_file=str(path),
                        license=meta.get("license"),
                    )
                )
            if components:
                return components

        # Fallback to v1 dependencies dict
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            for name, meta in islice(deps.items(), MAX_MANIFEST_COMPONENTS):
                if not isinstance(name, str) or len(name) > 512:
                    continue
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if not ver or not isinstance(ver, str):
                    continue
                c_ver = clean_version(ver)
                is_dev = bool(meta.get("dev", False))
                components.append(
                    Component(
                        name=name,
                        version=c_ver,
                        ecosystem="npm",
                        purl=make_purl("npm", name, c_ver),
                        is_dev=is_dev,
                        source_file=str(path),
                    )
                )

        return components
