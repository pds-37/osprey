"""Filesystem traversal helpers that refuse links and paths outside a scan root."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterator


def is_reparse_point(path: Path) -> bool:
    """Return true for symlinks and Windows reparse points; errors fail closed."""
    try:
        info = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if attributes & reparse_attribute:
        return True
    is_junction = getattr(path, "is_junction", None)
    try:
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _within_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def walk_workspace(
    root_path: str | Path,
    *,
    skip_dirs: set[str],
    max_depth: int,
) -> Iterator[tuple[Path, list[str], list[str], bool]]:
    """Walk only ordinary directories/files beneath the resolved workspace.

    The final boolean signals that a link, reparse point, or unresolvable entry
    was skipped in this directory. Symlinked directories are pruned before the
    walker can descend into them.
    """
    root = Path(root_path).resolve(strict=True)
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if is_reparse_point(current_path) or not _within_root(root, current_path):
            directories.clear()
            continue
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            directories.clear()
            continue

        skipped = False
        safe_directories: list[str] = []
        for name in directories:
            child = current_path / name
            if name in skip_dirs or name.startswith("."):
                continue
            if is_reparse_point(child) or not _within_root(root, child):
                skipped = True
                continue
            try:
                if child.is_dir():
                    safe_directories.append(name)
                else:
                    skipped = True
            except OSError:
                skipped = True
        directories[:] = safe_directories if depth < max_depth else []

        safe_files: list[str] = []
        for name in filenames:
            child = current_path / name
            if is_reparse_point(child) or not _within_root(root, child):
                skipped = True
                continue
            try:
                if child.is_file():
                    safe_files.append(name)
                else:
                    skipped = True
            except OSError:
                skipped = True
        yield current_path, list(directories), safe_files, skipped
