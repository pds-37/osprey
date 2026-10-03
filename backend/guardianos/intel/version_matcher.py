"""Robust semantic and distribution package version comparison."""

import re
from typing import List, Tuple


def _split_version(version_str: str) -> List[Tuple[int, str]]:
    """Parse version into numeric and alphabetic tokens while preserving revisions."""
    # Strip epoch if present (e.g., '1:2.4.0' -> '2.4.0')
    cleaned = version_str.split(":", 1)[-1].strip()
    
    # Split by dots, hyphens, and tildes into segments
    segments = re.split(r"[.\-~+]+", cleaned)
    tokens: List[Tuple[int, str]] = []
    
    for seg in segments:
        sub_tokens = re.findall(r"(\d+|\D+)", seg)
        for tok in sub_tokens:
            if tok.isdigit():
                tokens.append((int(tok), ""))
            else:
                tokens.append((0, tok.lower()))
    return tokens


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.
    Returns:
       -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    p1 = _split_version(v1)
    p2 = _split_version(v2)

    # Pad with zeros
    max_len = max(len(p1), len(p2))
    p1_padded = p1 + [(0, "")] * (max_len - len(p1))
    p2_padded = p2 + [(0, "")] * (max_len - len(p2))

    for (num1, str1), (num2, str2) in zip(p1_padded, p2_padded):
        if num1 < num2:
            return -1
        if num1 > num2:
            return 1
        if str1 < str2:
            return -1
        if str1 > str2:
            return 1
    return 0


def is_version_affected(installed: str, affected_ranges: List[str], fixed_versions: List[str]) -> bool:
    """
    Determine if an installed version matches affected ranges or is below fixed versions.
    """
    if not installed or installed == "unknown":
        return False

    # 1. If explicit fixed versions exist and installed is lower than any fixed version
    for fixed in fixed_versions:
        if compare_versions(installed, fixed) < 0:
            return True

    # 2. Check explicit range rules
    for rule in affected_ranges:
        rule = rule.strip()
        if rule.startswith("<="):
            target = rule[2:].strip()
            if compare_versions(installed, target) <= 0:
                return True
        elif rule.startswith("<"):
            target = rule[1:].strip()
            if compare_versions(installed, target) < 0:
                return True
        elif rule.startswith("=="):
            target = rule[2:].strip()
            if compare_versions(installed, target) == 0:
                return True
        elif rule == installed:
            return True

    return False
