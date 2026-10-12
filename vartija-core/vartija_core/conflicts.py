"""Conflict detector: surfaces tensions between actions and obligations.

Deterministic on purpose. The rules are in config/conflicts.yaml so a domain expert
can add one in minutes; an LLM may *explain* a conflict but never decides it.
"""

from __future__ import annotations

from .config import Config


def detect(config: Config, *, actions: list[str], flags: dict) -> list[dict]:
    acts = set(actions)
    active_flags = {k for k, v in (flags or {}).items() if v}
    found = []
    for rule in config.conflicts:
        if "when_all" in rule and not set(rule["when_all"]) <= acts:
            continue
        if "when_flags_all" in rule and not set(rule["when_flags_all"]) <= active_flags:
            continue
        if "when_all" not in rule and "when_flags_all" not in rule:
            continue
        if set(rule.get("unless_any", [])) & acts:
            continue
        found.append({k: rule[k] for k in ("id", "title", "detail", "suggestion") if k in rule})
    return found
