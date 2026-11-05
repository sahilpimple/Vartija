"""Stricter citation checks: the cited passage must exist, must have been retrieved, and
the quoted words must actually appear in it.

agents.py already rejects citation IDs that were not retrieved. This adds the second half:
a model can cite a real paragraph and still misquote it. ``verify_citations`` checks each
``{"id": ..., "quote": ...}`` pair and says why anything was rejected, so the UI can show
"citation rejected: quote not found in nis2:art23-4" instead of a silent drop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s%./()\-]")


def _norm(text: str) -> str:
    text = text.replace("–", "-").replace("—", "-").replace("’", "'")
    return _WS.sub(" ", _PUNCT.sub(" ", text.lower())).strip()


def quote_in_text(quote: str, text: str, min_ratio: float = 0.92) -> tuple[bool, float]:
    """True if ``quote`` appears in ``text`` exactly (after normalising case, spacing and
    punctuation) or near-exactly (OCR/PDF noise). Returns (found, similarity 0..1)."""
    q, t = _norm(quote), _norm(text)
    if not q:
        return False, 0.0
    if q in t:
        return True, 1.0
    # best window of the same length, measured by difflib
    best = 0.0
    n, step = len(q), max(1, len(q) // 8)
    for start in range(0, max(1, len(t) - n + 1), step):
        r = SequenceMatcher(None, q, t[start:start + n + n // 10]).ratio()
        if r > best:
            best = r
            if best >= 0.999:
                break
    return best >= min_ratio, round(best, 3)


@dataclass
class CitationCheck:
    id: str
    quote: str
    ok: bool
    reason: str
    similarity: float = 0.0


def verify_citations(citations: list, retriever, retrieved_ids: set[str] | None = None,
                     min_ratio: float = 0.92) -> tuple[list[CitationCheck], list[CitationCheck]]:
    """Check citations given as ``"id"`` strings or ``{"id", "quote"}`` dicts.

    A citation is rejected when the ID is unknown, when it was not in the retrieved set
    (if one is given), or when a quote is supplied and not found in the passage.
    Returns (accepted, rejected); every item carries a human-readable ``reason``.
    """
    accepted: list[CitationCheck] = []
    rejected: list[CitationCheck] = []
    for item in citations or []:
        if isinstance(item, dict):
            cid, quote = str(item.get("id", "")).strip("[] "), str(item.get("quote") or "")
        else:
            cid, quote = str(item).strip("[] "), ""
        chunk = retriever.get(cid)
        if chunk is None:
            rejected.append(CitationCheck(cid, quote, False, "unknown passage id"))
            continue
        if retrieved_ids is not None and cid not in retrieved_ids:
            rejected.append(CitationCheck(cid, quote, False, "passage was not in the retrieved context"))
            continue
        if quote:
            found, sim = quote_in_text(quote, chunk.title + " " + chunk.text, min_ratio)
            if not found:
                rejected.append(CitationCheck(cid, quote, False, "quoted text not found in the passage", sim))
                continue
            accepted.append(CitationCheck(cid, quote, True, "quote verified", sim))
        else:
            accepted.append(CitationCheck(cid, quote, True, "id verified (no quote given)"))
    return accepted, rejected
