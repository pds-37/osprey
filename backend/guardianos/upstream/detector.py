"""Deterministic heuristics engine for analyzing upstream commit security relevance."""

import re
from typing import List, Tuple
from guardianos.upstream.models import ChangeClassification

# Signal definitions with associated regexes and weights adhering to GuardianOS specifications
SECURITY_SIGNALS: List[Tuple[str, str, float]] = [
    # Signal Name, Regex Pattern, Weight
    ("integer conversion", r"\b(integer\s+(conversion|overflow|truncation)|int\s+conversion|arithmetic\s+overflow)\b", 0.35),
    ("bounds calculation", r"\b(bounds?\s+(calculation|check(ing)?)|out[\s-]of[\s-]bounds|oob|boundary\s+check)\b", 0.35),
    ("memory allocation", r"\b(memory\s+allocat(ion|e)|alloc_sz|malloc|calloc|buffer\s+allocat)\b", 0.30),
    ("buffer overflow", r"\b(buffer\s+overflow|stack\s+overflow|heap\s+overflow|heap-buffer-overflow)\b", 0.40),
    ("use after free", r"\b(use[\s-]after[\s-]free|uaf|double\s+free)\b", 0.40),
    ("input sanitization", r"\b(sanitiz(e|ation)|untrusted\s+input|input\s+validation|escape\s+string)\b", 0.30),
    ("parser validation", r"\b(parser\s+crash|malformed\s+input|crafted\s+file|corrupt\s+data)\b", 0.30),
    ("privilege handling", r"\b(privilege\s+escalat|permission\s+check|unauthorized|access\s+control)\b", 0.35),
    ("denial of service", r"\b(dos|denial\s+of\s+service|infinite\s+loop|catastrophic\s+backtracking)\b", 0.30),
    ("injection defense", r"\b(command\s+injection|code\s+execution|rce|arbitrary\s+read)\b", 0.45),
    ("null pointer dereference", r"\b(null\s+pointer|nullptr\s+deref|segfault|crash\s+fix)\b", 0.25),
]


def analyze_commit_heuristics(message: str, diff_text: str = "") -> Tuple[ChangeClassification, float, List[str], str]:
    """
    Analyze commit message and optional diff for suspicious security-relevant changes.
    Returns (classification, confidence, detected_signals, reasoning).
    """
    combined_text = f"{message}\n{diff_text}".lower()
    detected_signals: List[str] = []
    total_score = 0.0

    for signal_name, pattern, weight in SECURITY_SIGNALS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            detected_signals.append(signal_name)
            total_score += weight

    confidence = min(0.98, round(total_score, 2))

    if confidence >= 0.40:
        classification = ChangeClassification.SUSPECTED_SECURITY_CHANGE
        reasoning = (
            f"Heuristic pattern detection matched {len(detected_signals)} security signals: "
            f"{', '.join(detected_signals)}. Change modifies safety-critical bounds or allocation logic."
        )
    else:
        classification = ChangeClassification.UNKNOWN
        reasoning = "Commit does not exhibit strong deterministic security-fix signatures."

    return classification, confidence, detected_signals, reasoning
