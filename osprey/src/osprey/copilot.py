"""Shared read-only, evidence-grounded copilot response primitives.

Providers may select from server-created fact keys, but they never author security
claims. Osprey renders every claim from normalized deterministic facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class CopilotFact:
    key: str
    text: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CopilotContext:
    finding_id: str
    context_hash: str
    vulnerability_id: str = "UNKNOWN"
    package: str = "UNKNOWN"
    facts: tuple[CopilotFact, ...] = ()
    unknowns: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    next_steps: tuple[tuple[str, str], ...] = ()
    security_confidence: str = "UNKNOWN"
    runtime_states: tuple[tuple[str, str], ...] = ()
    severity: str = "UNKNOWN"
    reachability_status: str = "UNKNOWN"
    reachability_confidence: float | str = "UNKNOWN"
    untrusted_project_content: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ProviderSelection:
    fact_keys: tuple[str, ...]
    next_step_keys: tuple[str, ...] = ()


class AIProvider(Protocol):
    """A provider can choose existing evidence keys; it cannot create claims."""

    provider_id: str

    def select(self, question: str, context: CopilotContext) -> ProviderSelection: ...


class EvidenceOnlyProvider:
    """Deterministic provider used when no external model is configured."""

    provider_id = "evidence-only"

    def select(self, question: str, context: CopilotContext) -> ProviderSelection:
        # Question routing changes order only; all facts remain in the response.
        text = question.casefold()
        preferred: tuple[str, ...]
        if any(token in text for token in ("runtime", "loaded", "exercised", "running")):
            preferred = ("runtime",)
        elif any(token in text for token in ("reach", "call path", "symbol", "function")):
            preferred = ("reachability", "symbols")
        elif any(token in text for token in ("remediat", "verification", "verified", "after remediation")):
            preferred = ("remediation", "risk")
        elif any(token in text for token in ("risk", "act now", "decision", "score")):
            preferred = ("risk", "advisory")
        elif any(token in text for token in ("version", "cve", "vulnerab", "advisory")):
            preferred = ("finding", "version", "advisory")
        else:
            preferred = ()
        keys = [fact.key for fact in context.facts]
        ordered = [key for key in preferred if key in keys]
        ordered.extend(key for key in keys if key not in ordered)
        step_keys = [key for key, _ in context.next_steps]
        if "runtime" in text or "loaded" in text or "exercised" in text:
            steps = ["collect-runtime"]
        elif "reach" in text or "path" in text:
            steps = ["inspect-source"]
        elif "remediat" in text or "verification" in text:
            steps = ["review-remediation"]
        elif "risk" in text or "vulnerab" in text:
            steps = ["review-advisory"]
        else:
            steps = []
        ordered_steps = [key for key in steps if key in step_keys]
        ordered_steps.extend(key for key in step_keys if key not in ordered_steps)
        return ProviderSelection(
            fact_keys=tuple(ordered),
            next_step_keys=tuple(ordered_steps),
        )


def validate_selection(selection: ProviderSelection, context: CopilotContext) -> bool:
    """Reject provider selectors that refer to any fact or action Osprey did not supply."""
    fact_keys = {fact.key for fact in context.facts}
    step_keys = {key for key, _ in context.next_steps}
    return (
        len(selection.fact_keys) <= len(fact_keys)
        and len(set(selection.fact_keys)) == len(selection.fact_keys)
        and set(selection.fact_keys).issubset(fact_keys)
        and len(selection.next_step_keys) <= len(step_keys)
        and len(set(selection.next_step_keys)) == len(selection.next_step_keys)
        and set(selection.next_step_keys).issubset(step_keys)
    )


def render_facts(context: CopilotContext, selection: ProviderSelection) -> tuple[CopilotFact, ...]:
    """Order facts per a validated selection, appending omitted facts deterministically."""
    by_key = {fact.key: fact for fact in context.facts}
    selected = [by_key[key] for key in selection.fact_keys]
    seen = set(selection.fact_keys)
    selected.extend(fact for fact in context.facts if fact.key not in seen)
    return tuple(selected)


def render_next_steps(context: CopilotContext, selection: ProviderSelection) -> tuple[str, ...]:
    by_key = dict(context.next_steps)
    selected = [by_key[key] for key in selection.next_step_keys]
    seen = set(selection.next_step_keys)
    selected.extend(text for key, text in context.next_steps if key not in seen)
    return tuple(selected)
