"""Ingest a document into the citable corpus.

    python scripts/ingest_docs.py path/to/rules.pdf --prefix src --tags src,rules
    python scripts/ingest_docs.py policy.md --prefix pol --out corpus/policy.md \
        --heading '^(?P<num>[A-Z]{2}-\\d+)\\s+(?P<title>.+)$'

Prints a summary: paragraph count, duplicate numbers, cross-references, and the first IDs,
so you can see at once whether the heading patterns fit the document.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vartija_core.docingest import (DEFAULT_HEADINGS, extract_refs, read_document,  # noqa: E402
                                    split_numbered, write_corpus)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("document", type=Path)
    ap.add_argument("--prefix", required=True, help="ID prefix, e.g. 'nis2' -> nis2:23(4)")
    ap.add_argument("--tags", default="", help="comma-separated corpus tags (default: prefix)")
    ap.add_argument("--out", type=Path, help="output markdown (default: corpus/<prefix>.md)")
    ap.add_argument("--heading", action="append", default=[],
                    help="extra heading regex with a (?P<num>...) group; tried before the defaults")
    ap.add_argument("--only-custom", action="store_true", help="use only --heading patterns")
    ap.add_argument("--note", default="", help="source/licence note written into the file")
    args = ap.parse_args()

    headings = args.heading + ([] if args.only_custom else DEFAULT_HEADINGS)
    paras = split_numbered(read_document(args.document), args.prefix, headings)
    refs = extract_refs(paras)
    tags = [t.strip() for t in (args.tags or args.prefix).split(",") if t.strip()]
    out = write_corpus(paras, args.out or ROOT / "corpus" / f"{args.prefix}.md", tags, refs,
                       source_note=args.note or f"ingested from {args.document.name}")

    dupes = [p.id for p in paras if "~" in p.id]
    empty = [p.id for p in paras if not p.text]
    print(f"{len(paras)} paragraphs -> {out}")
    print(f"{sum(len(v) for v in refs.values())} cross-references across {len(refs)} paragraphs")
    if dupes:
        print(f"WARNING {len(dupes)} duplicate numbers (check heading patterns): {dupes[:8]}")
    if empty:
        print(f"note: {len(empty)} heading-only paragraphs: {empty[:8]}")
    print("first IDs:", ", ".join(p.id for p in paras[:12]))


if __name__ == "__main__":
    main()
