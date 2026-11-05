"""Files added from the dashboard: rule documents become citable corpus, data files are kept as evidence.

Layout under ``upload_dir`` (default ``./data``, git-ignored because challenge material is
usually confidential)::

    data/
      originals/<name>            the file exactly as uploaded
      corpus/<prefix>.md          citable paragraphs (documents only)
      corpus/<prefix>.refs.json   cross-references
      manifest.json               name, kind, sha256, size, who, when, paragraph count

Documents (.pdf .md .txt .html .htm) go through ``docingest`` so every paragraph keeps the
document's own numbering. Everything else in ``DATA_TYPES`` is stored with its SHA-256 so
it can be referenced as evidence; nothing is executed or parsed.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .docingest import DEFAULT_HEADINGS, extract_refs, load_refs, read_document, split_numbered, write_corpus
from .rag import load_corpus

DOC_TYPES = {".pdf", ".md", ".txt", ".html", ".htm"}
DATA_TYPES = {".csv", ".xlsx", ".xls", ".json", ".yaml", ".yml", ".zip", ".docx", ".pptx", ".png", ".jpg",
              ".jpeg", ".xml", ".dwg", ".dxf", ".ifc", ".step", ".stp"}


class SourceError(Exception):
    pass


def _safe_name(name: str) -> str:
    base = Path(name).name  # drops any directory part ("../../etc/passwd" -> "passwd")
    base = re.sub(r"[^A-Za-z0-9._ -]+", "_", base).strip(" .")
    if not base:
        raise SourceError("file name is empty after cleaning")
    return base[:120]


def _prefix_from(name: str) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", Path(name).stem.lower()).strip("-")
    return (stem or "doc")[:32]


def _manifest_path(root: Path) -> Path:
    return Path(root) / "manifest.json"


def _read_manifest(root: Path) -> dict:
    p = _manifest_path(root)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _write_manifest(root: Path, data: dict) -> None:
    p = _manifest_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_upload(root: Path, filename: str, data: bytes, *, prefix: str = "", heading: str = "",
                reserved_prefixes: set[str] | None = None, uploaded_by: str = "") -> dict:
    root = Path(root)
    name = _safe_name(filename)
    ext = Path(name).suffix.lower()
    if ext not in DOC_TYPES | DATA_TYPES:
        raise SourceError(f"file type '{ext or 'none'}' is not accepted; documents: {sorted(DOC_TYPES)}, "
                          f"data: {sorted(DATA_TYPES)}")
    if not data:
        raise SourceError("file is empty")
    manifest = _read_manifest(root)
    if name in manifest:
        raise SourceError(f"'{name}' is already uploaded; delete it first to replace it")
    sha = hashlib.sha256(data).hexdigest()
    info = {"name": name, "kind": "document" if ext in DOC_TYPES else "data", "sha256": sha, "bytes": len(data),
            "uploaded_by": uploaded_by, "uploaded_at": datetime.now(timezone.utc).isoformat()}
    originals = root / "originals"
    originals.mkdir(parents=True, exist_ok=True)
    (originals / name).write_bytes(data)

    if info["kind"] == "document":
        pre = re.sub(r"[^a-z0-9-]+", "-", (prefix or _prefix_from(name)).lower()).strip("-")[:32] or "doc"
        taken = set(reserved_prefixes or set()) | {m.get("prefix") for m in manifest.values() if m.get("prefix")}
        if pre in taken:
            (originals / name).unlink(missing_ok=True)
            raise SourceError(f"citation prefix '{pre}' is already used; choose another prefix")
        headings = ([heading] if heading else []) + DEFAULT_HEADINGS
        try:
            text = read_document(originals / name)
            paras = split_numbered(text, pre, headings)
        except Exception as exc:  # unreadable PDF, bad regex, missing pypdf
            (originals / name).unlink(missing_ok=True)
            raise SourceError(f"could not read the document: {exc}") from exc
        if not any(p.text for p in paras):
            (originals / name).unlink(missing_ok=True)
            raise SourceError("no text found (is it a scanned PDF? it needs OCR first)")
        write_corpus(paras, root / "corpus" / f"{pre}.md", tags=[pre, "uploaded"], refs=extract_refs(paras),
                     source_note=f"uploaded {name} sha256={sha}")
        info.update(prefix=pre, paragraphs=len(paras),
                    numbered=sum(1 for p in paras if p.num != "preamble"),
                    duplicates=[p.id for p in paras if "~" in p.id][:10],
                    sample_ids=[p.id for p in paras[:8]])
    manifest[name] = info
    _write_manifest(root, manifest)
    return info


def delete_upload(root: Path, name: str) -> dict:
    root = Path(root)
    manifest = _read_manifest(root)
    info = manifest.pop(name, None)
    if info is None:
        raise SourceError(f"no uploaded source named '{name}'")
    (root / "originals" / name).unlink(missing_ok=True)
    if info.get("prefix"):
        (root / "corpus" / f"{info['prefix']}.md").unlink(missing_ok=True)
        (root / "corpus" / f"{info['prefix']}.refs.json").unlink(missing_ok=True)
    _write_manifest(root, manifest)
    return info


def list_uploads(root: Path) -> list[dict]:
    return sorted(_read_manifest(root).values(), key=lambda m: m.get("uploaded_at", ""), reverse=True)


def builtin_sources(corpus_dir: Path) -> list[dict]:
    out: dict[str, int] = {}
    for c in load_corpus(corpus_dir):
        out[c.source] = out.get(c.source, 0) + 1
    return [{"name": k, "paragraphs": v} for k, v in sorted(out.items())]


def load_uploaded_corpus(root: Path):
    d = Path(root) / "corpus"
    return load_corpus(d) if d.is_dir() else []


def load_uploaded_refs(root: Path) -> dict:
    d = Path(root) / "corpus"
    return load_refs(d) if d.is_dir() else {}
