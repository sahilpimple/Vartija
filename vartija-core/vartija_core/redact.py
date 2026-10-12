"""Personal-data redaction before anything is sent to a language model.

Replaces values with stable placeholders (``<EMAIL_1>``) so the model can still reason
about "the same user" without seeing who it is. The mapping stays on the server.
Regexes are a floor, not a ceiling: at the event, consider adding an NER model or
client-side redaction (e.g. a small Gemma model in the browser).
"""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    # Finnish personal identity code (henkilötunnus): DDMMYY, century sign, 3 digits, check char.
    ("HETU", re.compile(r"\b\d{6}[-+A-FU-Y]\d{3}[0-9A-FHJ-NPR-Y]\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b")),
    # International (+358 40 123 4567) or national (040 123 4567) numbers. Starting with
    # "+" or "0" avoids matching dates like 2026-11-07 or counts like 1500000.
    ("PHONE", re.compile(r"(?<![\w.:-])(?:\+\d{1,3}[ \-]?|0)\d{1,3}(?:[ \-]?\d){6,10}(?![\w.:-])")),
]


class Redactor:
    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def _token(self, kind: str, value: str) -> str:
        for token, original in self.mapping.items():
            if original == value and token.startswith(f"<{kind}_"):
                return token
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"<{kind}_{self._counters[kind]}>"
        self.mapping[token] = value
        return token

    def redact(self, text: str) -> str:
        for kind, pattern in PATTERNS:
            text = pattern.sub(lambda m, k=kind: self._token(k, m.group(0)), text)
        return text

    def restore(self, text: str) -> str:
        for token, original in self.mapping.items():
            text = text.replace(token, original)
        return text


def redact_text(text: str) -> str:
    return Redactor().redact(text)
