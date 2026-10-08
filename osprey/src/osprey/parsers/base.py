"""Base protocol and utilities for manifest parsers.

Assumptions and Limits:
- Parsers read file contents strictly as plain text (or JSON/TOML/YAML structured data).
- Scanned target repositories are never executed, installed, or imported.
- Version strings are sanitized to clean semantic versions where possible.
"""

from __future__ import annotations

import re
import os
import stat
from pathlib import Path
from typing import List, Protocol, runtime_checkable

from osprey.models import Component
from osprey.filesystem import is_reparse_point


MAX_MANIFEST_BYTES = 20_000_000
MAX_MANIFEST_COMPONENTS = 20_000


def read_bounded_text(path: Path, *, max_bytes: int = MAX_MANIFEST_BYTES) -> str:
    """Read one ordinary non-link manifest with a strict byte ceiling."""
    if is_reparse_point(path):
        raise ValueError("manifest links and reparse points are not followed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise ValueError("manifest is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise ValueError("manifest exceeds the configured size limit")
        return raw.decode("utf-8", errors="replace")
    finally:
        os.close(descriptor)

try:
    from packageurl import PackageURL
except ImportError:  # pragma: no cover
    PackageURL = None  # type: ignore


def clean_version(version_str: str) -> str:
    """Normalize semver range specifiers to isolate a base version string."""
    if not version_str:
        return "0.0.0"
    cleaned = re.sub(r"^[~^>=<!\s]+", "", version_str.strip())
    # Handle ranges separated by commas or whitespace (e.g. '>=1.0.0, <2.0.0' -> '1.0.0')
    cleaned = re.split(r"[,;\s]+", cleaned)[0].strip()
    return cleaned or "0.0.0"


def make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a canonical PackageURL string."""
    eco = ecosystem.lower()
    clean_ver = clean_version(version)
    if PackageURL:
        try:
            return PackageURL(type=eco, name=name.lower(), version=clean_ver).to_string()
        except Exception:
            pass
    return f"pkg:{eco}/{name.lower()}@{clean_ver}"


@runtime_checkable
class Parser(Protocol):
    """Protocol defining file detection and component extraction for a manifest parser."""

    name: str

    def detect(self, path: Path) -> bool:
        """Return True if this parser can process the specified file."""
        ...

    def parse(self, path: Path) -> List[Component]:
        """Parse file as text and extract discovered components."""
        ...
