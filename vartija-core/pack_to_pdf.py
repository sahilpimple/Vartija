"""Convert an exported audit pack (JSON) into a PDF.

    pip install reportlab
    python scripts/pack_to_pdf.py                                         # newest pack in Downloads/Desktop/here
    python scripts/pack_to_pdf.py vartija-audit-pack-<id>.json            # -> same name .pdf
    python scripts/pack_to_pdf.py pack.json -o report.pdf

The JSON comes from the dashboard's "JSON" button or GET /cases/{id}/export.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape


def when(iso: str | None) -> str:
    if not iso:
        return "–"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%d %b %Y %H:%M")
    except ValueError:
        return iso


def build(pack: dict, out: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#555555"))
    mono = ParagraphStyle("m", parent=small, fontName="Courier")
    h1 = ParagraphStyle("h1", parent=ss["Title"], alignment=0, fontSize=18, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    P = lambda t, st=body: Paragraph(escape(str(t if t is not None else "–")), st)  # noqa: E731

    def table(header: list[str], rows: list[list], widths: list[float]) -> Table:
        data = [[Paragraph(f"<b>{escape(h)}</b>", small) for h in header]] + rows
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3)]))
        return t

    case, chain, clock = pack["case"], pack["chain"], pack["clock"]
    a = case.get("latest_assessment")
    story = [Paragraph("Audit pack", h1), P(case["title"]),
             P(f"Case {case['id']} · generated {when(pack.get('generated_at'))}", small), Spacer(1, 6)]

    ok = chain.get("ok")
    box = Table([[Paragraph(f"<b>{'Record intact' if ok else 'Record has been altered'}</b> · "
                            f"{chain.get('entries')} entries in the tamper-evident log", body)],
                 [P("Chain head (keep a copy outside the system):", small)],
                 [P(chain.get("head_hash"), mono)]], colWidths=[180 * mm])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#2e7d32" if ok else "#c62828")),
                             ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef7ee" if ok else "#fdeeee"))]))
    story += [box]

    owner = (case.get("grc") or {}).get("owner")
    owner = owner.get("name") if isinstance(owner, dict) else owner
    duties = ", ".join(k.replace("_", " ") for k, v in (case.get("flags") or {}).items() if v) or "none"
    story += [Paragraph("Summary", h2),
              table(["Status", "Asset", "Owner", "Detected", "Duties confirmed by a person"],
                    [[P(case.get("status")), P(case.get("asset_id")), P(owner), P(when(case.get("detected_at"))),
                      P(duties)]], [22, 32, 32, 34, 60])]

    rows = []
    for r in clock.get("regimes", []):
        for s in r.get("stages", []):
            status = f"done {when(s['completed_at'])}" if s.get("completed_at") else s["status"].replace("_", " ")
            rows.append([P(r["name"]), P(r["authority"]), P(s["label"]), P(when(s.get("due_at"))), P(status)])
    story += [Paragraph("Legal deadlines", h2), table(["Regime", "Authority", "Stage", "Due", "Status"], rows,
                                                       [42, 42, 32, 32, 32])]

    rows = [[P(when(e["occurred_at"])), P(e["type"]), P(f"{e['severity']} ({round(e['confidence'] * 100)}%)"),
             P(e["summary"]), P(" ".join(e.get("evidence_refs") or []), mono)] for e in case.get("events", [])]
    story += [Paragraph("What happened", h2), table(["When", "Type", "Severity", "Summary", "Evidence"], rows,
                                                     [26, 34, 22, 62, 36])]

    if a:
        flags = ", ".join(f"{k.replace('_', ' ')}: {'yes' if v else 'no'}" for k, v in a["flags"].items())
        story += [Paragraph("AI assessment (advisory)", h2),
                  P(f"{flags} · confidence {round(a['confidence'] * 100)}%"
                    + (" · human review required" if a.get("needs_human_review") else ""), small),
                  Spacer(1, 3), P(a.get("rationale")),
                  P("Sources cited: " + (", ".join(a.get("citations") or []) or "none"), small)]
        if a.get("rejected_citations"):
            story.append(P("Citations rejected by the system: " + ", ".join(a["rejected_citations"]), small))
        for k in a.get("conflicts") or []:
            story.append(P(f"Conflict for a person to decide: {k.get('title') or k.get('id')}"
                           + (f" – {k['suggestion']}" if k.get("suggestion") else ""), small))

    for d in pack.get("reports", []):
        story += [Paragraph(f"Report draft: {d['regime']} · {d['stage']} ({round(d['completeness'] * 100)}% complete)", h2),
                  table(["Field", "Value"], [[P(f["label"]), P(f["value"] or "missing")] for f in d["fields"]], [60, 120])]

    rows = [[P(r["seq"]), P(when(r["ts"])), P(f"{r['actor']} ({r['actor_kind']})"), P(r["action"]),
             P(r["entry_hash"][:24] + "…", mono)] for r in pack.get("audit_trail", [])]
    story += [Paragraph("Audit trail", h2), table(["#", "When", "Who", "What", "Entry hash"], rows, [10, 30, 45, 40, 55]),
              Spacer(1, 6),
              P("Each entry's hash includes the previous entry's hash, so changing or deleting any row breaks every "
                "hash after it. AI output is decision support; duties and approvals were confirmed by the named people.",
                small)]

    SimpleDocTemplate(str(out), pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm,
                      bottomMargin=14 * mm, title=f"Audit pack {case['id']}").build(story)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pack", type=Path, nargs="?", help="exported audit pack .json (default: the newest one found)")
    ap.add_argument("-o", "--out", type=Path, help="output .pdf (default: next to the JSON)")
    args = ap.parse_args()
    try:
        import reportlab  # noqa: F401
    except ImportError:
        raise SystemExit("Needs reportlab:  pip install reportlab")
    if args.pack is None:
        home = Path.home()
        places = [home / "Downloads", home / "OneDrive" / "Downloads", home / "Desktop",
                  home / "OneDrive" / "Desktop", Path.cwd()]
        found = [f for d in places if d.is_dir() for f in d.glob("vartija-audit-pack-*.json")]
        if not found:
            raise SystemExit("No vartija-audit-pack-*.json found in Downloads, Desktop or this folder.\n"
                             "Export one first: dashboard -> open a case -> JSON button.")
        args.pack = max(found, key=lambda f: f.stat().st_mtime)
        print(f"Using newest pack: {args.pack}")
    if not args.pack.exists():
        raise SystemExit(f"File not found: {args.pack}")
    out = args.out or args.pack.with_suffix(".pdf")
    build(json.loads(args.pack.read_text(encoding="utf-8")), out)
    print(f"PDF written: {out}")


if __name__ == "__main__":
    main()
