"""Turn source documents (laws, standards, rule books, policies, SOPs) into citable corpus chunks.

Citations can only be checked if every paragraph keeps the ID the document itself uses
("Article 23(4)", "Regulation 9.2.2.3", "Section 4.1"). This module keeps those IDs:

    text = read_document(Path("rules.pdf"))
    paras = split_numbered(text, prefix="src")       # -> [Paragraph(id="src:9.2.2.3", ...), ...]
    refs = extract_refs(paras)                       # -> {"src:9.2.2.3": ["src:9.2", ...]}
    write_corpus(paras, Path("corpus/src.md"), tags=["src"], refs=refs)

The output is the same ``## [id] Title`` markdown that ``rag.load_corpus`` reads, plus a
``<name>.refs.json`` sidecar with cross-references for ``HybridRetriever(refs=...)``.

Heading patterns are plain regexes with a ``num`` group (and optional ``title``) so a
new document style is a one-line addition, not a code change.
"""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# Line-start heading patterns, tried in order. ``num`` becomes part of the chunk ID.
DEFAULT_HEADINGS: list[str] = [
    r"^(?:Article|Art\.)\s+(?P<num>\d+[a-z]?(?:\(\d+\))*)\s*[.:\-–]?\s*(?P<title>.*)$",
    r"^(?:Regulation|Reg\.)\s+(?P<num>\d+(?:\.\d+)*)\s*[.:\-–]?\s*(?P<title>.*)$",
    r"^(?:Section|Sec\.)\s+(?P<num>\d+(?:\.\d+)*)\s*[.:\-–]?\s*(?P<title>.*)$",
    r"^(?:Annex|Appendix)\s+(?P<num>[IVXLC]+|[A-Z]|\d+)\s*[.:\-–]?\s*(?P<title>.*)$",
    # bare numbering: "4.1.2 Title" or "4.1.2. Title" (needs at least one dot so years and
    # quantities on their own line are not mistaken for headings)
    r"^(?P<num>\d+(?:\.\d+)+)\.?\s+(?P<title>[A-Z].{0,150})$",
]

# Cross-reference patterns found inside paragraph text; ``num`` is matched to known IDs.
DEFAULT_REFS: list[str] = [
    r"\b(?:Article|Art\.)\s+(?P<num>\d+[a-z]?(?:\(\d+\))*)",
    r"\b(?:Regulation|Reg\.)\s+(?P<num>\d+(?:\.\d+)*)",
    r"\b(?:Section|Sec\.)\s+(?P<num>\d+(?:\.\d+)*)",
    r"\b(?:paragraph|para\.)\s+(?P<num>\d+(?:\.\d+)*)",
    r"\b(?:Annex|Appendix)\s+(?P<num>[IVXLC]+|[A-Z]|\d+)\b",
]


@dataclass
class Paragraph:
    id: str
    num: str
    title: str
    text: str
    parent: str | None = None
    lines: list[str] = field(default_factory=list, repr=False)


def read_document(path: Path) -> str:
    """Plain text from .md/.txt/.html/.pdf. PDF needs ``pip install pypdf``."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in {".md", ".txt"}:
        return path.read_text(encoding="utf-8")
    if suffix in {".html", ".htm"}:
        raw = path.read_text(encoding="utf-8")
        raw = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
        raw = re.sub(r"(?i)<br\s*/?>|</(p|div|h\d|li|tr)>", "\n", raw)
        return html.unescape(re.sub(r"<[^>]+>", " ", raw))
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError("PDF ingestion needs: pip install pypdf  (or vartija-core[docs])") from exc
        reader = PdfReader(str(path))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    raise ValueError(f"unsupported document type: {suffix}")


def strip_repeated_lines(text: str, min_repeats: int = 3) -> str:
    """Drop lines that repeat many times (PDF page headers/footers, 'Page 3 of 90')."""
    lines = text.splitlines()
    norm = [re.sub(r"\d+", "#", ln.strip()) for ln in lines]
    counts = Counter(n for n in norm if n)
    return "\n".join(ln for ln, n in zip(lines, norm) if not n or counts[n] < min_repeats)


def _norm_id(num: str) -> str:
    return re.sub(r"\s+", "", num).strip(".").lower()


def _parent(num: str) -> str | None:
    if "(" in num:
        return num[: num.rfind("(")] or None
    return num.rsplit(".", 1)[0] if "." in num else None


def split_numbered(text: str, prefix: str, headings: list[str] | None = None,
                   strip_repeats: bool = True) -> list[Paragraph]:
    """Split text into paragraphs at numbered headings. Text before the first heading is
    kept as ``<prefix>:preamble``. Duplicate numbers get ``~2``, ``~3`` suffixes and are
    reported via the returned paragraphs, never silently merged."""
    if strip_repeats:
        text = strip_repeated_lines(text)
    pats = [re.compile(p) for p in (headings or DEFAULT_HEADINGS)]
    paras: list[Paragraph] = []
    current = Paragraph(id=f"{prefix}:preamble", num="preamble", title="Preamble", text="")
    seen: Counter = Counter()

    def flush() -> None:
        current.text = re.sub(r"[ \t]+", " ", "\n".join(current.lines)).strip()
        if current.text or current.num != "preamble":
            paras.append(current)

    for raw in text.splitlines():
        line = raw.strip()
        match = next((m for p in pats if (m := p.match(line))), None)
        if match:
            flush()
            num = _norm_id(match.group("num"))
            seen[num] += 1
            suffix = f"~{seen[num]}" if seen[num] > 1 else ""
            title = (match.groupdict().get("title") or "").strip()
            parent = _parent(num)
            current = Paragraph(id=f"{prefix}:{num}{suffix}", num=num, title=title or num,
                                text="", parent=f"{prefix}:{parent}" if parent else None)
        else:
            current.lines.append(line)
    flush()
    return paras


def extract_refs(paras: list[Paragraph], patterns: list[str] | None = None) -> dict[str, list[str]]:
    """Map each paragraph ID to the known paragraph IDs its text refers to (same document).
    A reference to a number we don't have (another document, a typo) is ignored here."""
    by_num: dict[str, str] = {}
    for p in paras:
        by_num.setdefault(p.num, p.id)
    pats = [re.compile(p, re.IGNORECASE) for p in (patterns or DEFAULT_REFS)]
    refs: dict[str, list[str]] = {}
    for p in paras:
        found: list[str] = []
        for pat in pats:
            for m in pat.finditer(p.text):
                target = by_num.get(_norm_id(m.group("num")))
                if target and target != p.id and target not in found:
                    found.append(target)
        if p.parent and p.parent in by_num.values() and p.parent not in found:
            found.append(p.parent)
        if found:
            refs[p.id] = found
    return refs


def write_corpus(paras: list[Paragraph], out_path: Path, tags: list[str],
                 refs: dict[str, list[str]] | None = None, source_note: str = "") -> Path:
    """Write ``## [id] Title`` markdown for ``rag.load_corpus`` and a refs sidecar."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"tags: {', '.join(tags)}", ""]
    if source_note:
        lines += [f"<!-- {source_note} -->", ""]
    for p in paras:
        lines += [f"## [{p.id}] {p.title}", p.text or "(heading only)", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    if refs:
        out_path.with_suffix(".refs.json").write_text(json.dumps(refs, indent=2), encoding="utf-8")
    return out_path


def load_refs(corpus_dir: Path) -> dict[str, list[str]]:
    """Merge every ``*.refs.json`` sidecar in a corpus directory."""
    merged: dict[str, list[str]] = {}
    for path in sorted(Path(corpus_dir).glob("*.refs.json")):
        for k, v in json.loads(path.read_text(encoding="utf-8")).items():
            merged.setdefault(k, [])
            merged[k] += [x for x in v if x not in merged[k]]
    return merged
