"""Parser for Python package manifests (requirements*.txt, pyproject.toml, poetry.lock).

Assumptions and Limitations:
- Parses requirement specifiers statically via regular expressions and standard TOML.
- Never executes setup.py or executes any shell commands.
- Automatically marks requirements-dev.txt or dev poetry groups as is_dev=True.
"""

from __future__ import annotations

import re
from itertools import islice
from pathlib import Path
from typing import Any, Dict, List

from osprey.models import Component
from osprey.parsers.base import MAX_MANIFEST_COMPONENTS, clean_version, make_purl, read_bounded_text

MAX_PYTHON_MANIFEST_BYTES = 10_000_000

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


class PyPiParser:
    """Parser for PyPI requirements files, pyproject.toml, and poetry.lock."""

    name: str = "pypi"

    def __init__(self) -> None:
        self.last_error: str | None = None

    def detect(self, path: Path) -> bool:
        name = path.name.lower()
        if name.endswith(".txt") and ("req" in name or "pip" in name):
            return True
        if name in ("pyproject.toml", "poetry.lock", "pipfile"):
            return True
        return False

    def parse(self, path: Path) -> List[Component]:
        self.last_error = None
        name = path.name.lower()
        try:
            if name.endswith(".txt"):
                return self._parse_requirements_txt(path)
            if name == "pyproject.toml":
                return self._parse_pyproject_toml(path)
            if name == "poetry.lock":
                return self._parse_poetry_lock(path)
            return []
        except Exception:
            self.last_error = "Python dependency manifest contains unsupported metadata"
            return []

    def _parse_requirements_txt(self, path: Path) -> List[Component]:
        components: List[Component] = []
        is_dev_file = any(token in path.name.lower() for token in ("dev", "test", "lint", "doc"))

        try:
            lines = read_bounded_text(path, max_bytes=MAX_PYTHON_MANIFEST_BYTES).splitlines()
        except Exception:
            self.last_error = "Python dependency manifest could not be read"
            return []

        for line in islice(lines, MAX_MANIFEST_COMPONENTS):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Strip inline comments
            if " #" in line:
                line = line.split(" #")[0].strip()

            # Handle environment markers (e.g. 'requests==2.31.0; python_version >= "3.8"')
            if ";" in line:
                line = line.split(";")[0].strip()

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+.*)?", line)
            if match:
                pkg_name = match.group(1).lower()
                raw_ver = match.group(2) or "0.0.0"
                c_ver = clean_version(raw_ver)

                components.append(
                    Component(
                        name=pkg_name,
                        version=c_ver,
                        ecosystem="PyPI",
                        purl=make_purl("pypi", pkg_name, c_ver),
                        is_dev=is_dev_file,
                        source_file=str(path),
                    )
                )

        return components[:MAX_MANIFEST_COMPONENTS]

    def _parse_pyproject_toml(self, path: Path) -> List[Component]:
        components: List[Component] = []
        try:
            content = read_bounded_text(path, max_bytes=MAX_PYTHON_MANIFEST_BYTES)
        except Exception:
            self.last_error = "Python dependency manifest could not be read"
            return []

        data: Dict[str, Any] = {}
        if tomllib:
            try:
                data = tomllib.loads(content)
            except Exception:
                self.last_error = "pyproject.toml could not be parsed"
                return []

        if not data:
            # Fallback naive parsing if tomllib is missing or broken
            return self._parse_toml_fallback(content, path)[:MAX_MANIFEST_COMPONENTS]

        # 1. PEP 621 [project.dependencies]
        project = data.get("project", {})
        prod_deps = project.get("dependencies", [])
        if isinstance(prod_deps, list):
            for dep in prod_deps:
                comp = self._parse_dep_string(dep, is_dev=False, source_file=str(path))
                if comp:
                    components.append(comp)

        # 2. PEP 621 [project.optional-dependencies]
        optional_deps = project.get("optional-dependencies", {})
        if isinstance(optional_deps, dict):
            for group, deps in optional_deps.items():
                is_dev = any(t in group.lower() for t in ("dev", "test", "lint", "doc"))
                if isinstance(deps, list):
                    for dep in deps:
                        comp = self._parse_dep_string(dep, is_dev=is_dev, source_file=str(path))
                        if comp:
                            components.append(comp)

        # 3. Poetry [tool.poetry.dependencies]
        tool_poetry = data.get("tool", {}).get("poetry", {})
        poetry_deps = tool_poetry.get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                ver = spec if isinstance(spec, str) else spec.get("version", "0.0.0") if isinstance(spec, dict) else "0.0.0"
                c_ver = clean_version(str(ver))
                components.append(
                    Component(
                        name=name.lower(),
                        version=c_ver,
                        ecosystem="PyPI",
                        purl=make_purl("pypi", name.lower(), c_ver),
                        is_dev=False,
                        source_file=str(path),
                    )
                )

        # 4. Poetry [tool.poetry.group.<group>.dependencies]
        groups = tool_poetry.get("group", {})
        if isinstance(groups, dict):
            for group_name, gdata in groups.items():
                is_dev = any(t in group_name.lower() for t in ("dev", "test", "lint", "doc"))
                gdeps = gdata.get("dependencies", {}) if isinstance(gdata, dict) else {}
                if isinstance(gdeps, dict):
                    for name, spec in gdeps.items():
                        ver = spec if isinstance(spec, str) else spec.get("version", "0.0.0") if isinstance(spec, dict) else "0.0.0"
                        c_ver = clean_version(str(ver))
                        components.append(
                            Component(
                                name=name.lower(),
                                version=c_ver,
                                ecosystem="PyPI",
                                purl=make_purl("pypi", name.lower(), c_ver),
                                is_dev=is_dev,
                                source_file=str(path),
                            )
                        )

        # 5. Legacy Poetry [tool.poetry.dev-dependencies]
        legacy_dev = tool_poetry.get("dev-dependencies", {})
        if isinstance(legacy_dev, dict):
            for name, spec in legacy_dev.items():
                ver = spec if isinstance(spec, str) else "0.0.0"
                c_ver = clean_version(str(ver))
                components.append(
                    Component(
                        name=name.lower(),
                        version=c_ver,
                        ecosystem="PyPI",
                        purl=make_purl("pypi", name.lower(), c_ver),
                        is_dev=True,
                        source_file=str(path),
                    )
                )

        return components[:MAX_MANIFEST_COMPONENTS]

    def _parse_poetry_lock(self, path: Path) -> List[Component]:
        components: List[Component] = []
        try:
            content = read_bounded_text(path, max_bytes=MAX_PYTHON_MANIFEST_BYTES)
        except Exception:
            self.last_error = "Python dependency manifest could not be read"
            return []

        # Split into [[package]] blocks
        blocks = content.split("[[package]]", MAX_MANIFEST_COMPONENTS + 1)
        for block in blocks[1:MAX_MANIFEST_COMPONENTS + 1]:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
            cat_m = re.search(r'category\s*=\s*"([^"]+)"', block)

            if name_m and ver_m:
                pkg_name = name_m.group(1).lower()
                c_ver = clean_version(ver_m.group(1))
                is_dev = False
                if cat_m and cat_m.group(1) == "dev":
                    is_dev = True

                components.append(
                    Component(
                        name=pkg_name,
                        version=c_ver,
                        ecosystem="PyPI",
                        purl=make_purl("pypi", pkg_name, c_ver),
                        is_dev=is_dev,
                        source_file=str(path),
                    )
                )
        return components[:MAX_MANIFEST_COMPONENTS]

    def _parse_dep_string(self, dep_str: str, is_dev: bool, source_file: str) -> Component | None:
        if not isinstance(dep_str, str):
            return None
        dep_str = dep_str.strip()
        if ";" in dep_str:
            dep_str = dep_str.split(";")[0].strip()
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+.*)?", dep_str)
        if m:
            pkg_name = m.group(1).lower()
            raw_ver = m.group(2) or "0.0.0"
            c_ver = clean_version(raw_ver)
            return Component(
                name=pkg_name,
                version=c_ver,
                ecosystem="PyPI",
                purl=make_purl("pypi", pkg_name, c_ver),
                is_dev=is_dev,
                source_file=source_file,
            )
        return None

    def _parse_toml_fallback(self, content: str, path: Path) -> List[Component]:
        components: List[Component] = []
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and "dependencies" in line.lower():
                in_deps = True
                continue
            if line.startswith("[") and "dependencies" not in line.lower():
                in_deps = False
                continue
            if in_deps:
                m = re.match(r'^"?([a-zA-Z0-9_\-\.]+)"?\s*=\s*"([^"]+)"', line)
                if m:
                    pkg_name = m.group(1).lower()
                    if pkg_name == "python":
                        continue
                    c_ver = clean_version(m.group(2))
                    components.append(
                        Component(
                            name=pkg_name,
                            version=c_ver,
                            ecosystem="PyPI",
                            purl=make_purl("pypi", pkg_name, c_ver),
                            is_dev=False,
                            source_file=str(path),
                        )
                    )
        return components[:MAX_MANIFEST_COMPONENTS]
