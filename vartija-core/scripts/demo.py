"""Narrated end-to-end run of the stage demo, in one process, no server needed.

    python scripts/demo.py                  # telecom credential-stuffing story
    VARTIJA_SECTOR=industrial python scripts/demo.py --story plc

Use it to rehearse, to check the core still works after changes, and as the fallback
if the live UI fails on stage (it prints every step and timing).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from vartija_core.api import create_app  # noqa: E402
from vartija_core.client import encode  # noqa: E402
from vartija_core.security import sign  # noqa: E402
from vartija_core.settings import Settings, get_settings  # noqa: E402

CISO = {"X-User": "aino.virtanen", "X-Roles": "ciso"}
MGMT = {"X-User": "pekka.ceo", "X-Roles": "management"}
AI = {"X-User": "vartija-agent", "X-User-Kind": "ai"}

STORIES = {
    "portal": {
        "sector": "telecom", "asset_id": "web-portal-01", "regime": "nis2_fi",
        "events": [
            ("auth.anomaly", "medium", 0.6, "Login failure rate on the customer portal 40x above baseline.",
             {"malicious": True}),
            ("auth.credential_stuffing", "high", 0.9,
             "Credential stuffing confirmed; 4,200 customer accounts accessed, incl. jane.doe@example.com.",
             {"users_affected": 4200, "malicious": True, "cross_border": True, "personal_data": True,
              "iocs": ["185.220.101.0/24", "UA: python-requests/2.31"]}),
        ],
    },
    "plc": {
        "sector": "industrial", "asset_id": "plc-line-3", "regime": "cra",
        "events": [
            ("vuln.exploited_in_wild", "high", 0.8,
             "Threat intel: active exploitation of an auth bypass in DA-PLC-4 firmware 4.2.",
             {"actively_exploited": True, "product_affected": True, "iocs": ["CVE-2026-0000 (placeholder)"]}),
        ],
    },
}


def say(step: str, text_: str = "") -> None:
    print(f"\n\033[1m{step}\033[0m {text_}")


def fmt(seconds: int) -> str:
    h, rem = divmod(max(seconds, 0), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--story", choices=sorted(STORIES), default="portal")
    args = ap.parse_args()
    story = STORIES[args.story]
    base = get_settings()
    tmp = Path(tempfile.mkdtemp())
    settings = Settings(database_url=f"sqlite:///{tmp / 'demo.db'}", event_secret="demo-secret",
                        config_dir=base.config_dir, corpus_dir=base.corpus_dir, seed_dir=base.seed_dir,
                        sector=story["sector"], llm_backend=base.llm_backend, llm_model=base.llm_model,
                        llm_base_url=base.llm_base_url, llm_api_key=base.llm_api_key)
    app = create_app(settings)
    c = TestClient(app)
    t_start = time.perf_counter()
    corr = f"demo-{uuid.uuid4().hex[:6]}"

    say("1. DETECT", f"ARCC-X sends {len(story['events'])} signed event(s)")
    case_id = None
    for i, (etype, sev, conf, summary, attrs) in enumerate(story["events"]):
        ev = {"event_id": f"{corr}-{i}", "source": "arcc-x", "event_type": etype,
              "occurred_at": (datetime.now(timezone.utc) - timedelta(minutes=10 - i)).isoformat(),
              "correlation_id": corr, "asset_id": story["asset_id"], "severity": sev, "confidence": conf,
              "summary": summary, "attributes": attrs, "evidence_refs": [f"evidence://{corr}/{i}.log"]}
        body = encode(ev)
        r = c.post("/events", content=body, headers={"Content-Type": "application/json",
                                                     **sign(settings.event_secret, body)})
        case_id = r.json()["case_id"]
        print(f"   {etype:<28} -> case {case_id[:8]} duplicate={r.json()['duplicate']}")
    body = encode(ev)  # resend the last one: ARCC-X retry after a timeout
    dup = c.post("/events", content=body, headers={"Content-Type": "application/json",
                                                   **sign(settings.event_secret, body)}).json()
    print(f"   retry of the same event      -> duplicate={dup['duplicate']} (no second case)")

    clock = c.get(f"/cases/{case_id}/clock", headers=CISO).json()
    nd = clock["next_due"]
    say("2. CLOCK STARTS", f"{nd['regime']} {nd['label']}: {fmt(nd['seconds_remaining'])} left")

    say("3. CONTEXT", "from CyberGRC-AI")
    detail = c.get(f"/cases/{case_id}", headers=CISO).json()
    g = detail["grc"]
    print(f"   asset: {g['asset'].get('name')} | owner: {(g['owner'] or {}).get('name')}")
    print(f"   risks: {[r['id'] + ' ' + r['title'] for r in g['risks']]}")
    print(f"   open findings: {[f['id'] + ' ' + f['title'] for f in g['findings']]}")

    say("4. ASSESS", "AI significance assessment (advisory)")
    a = c.post(f"/cases/{case_id}/assess", json={}, headers=CISO).json()
    print(f"   engine={a['engine']}  confidence={a['confidence']}")
    print(f"   flags={a['flags']}")
    print(f"   rationale: {a['rationale']}")
    for cid, title in a["citation_texts"].items():
        print(f"   cites [{cid}] {title}")
    if a["rejected_citations"]:
        print(f"   REJECTED unsupported citations: {a['rejected_citations']}")

    say("5. CONFLICTS", f"{len(a['conflicts'])} found")
    for k in a["conflicts"]:
        print(f"   ! {k['title']} -> {k['suggestion']}")

    say("6. HUMAN CONFIRMS", "CISO accepts the flags; clocks now count only for regimes that apply")
    c.post(f"/cases/{case_id}/flags", headers=CISO, json={"flags": a["flags"], "reason": "reviewed on call"})
    clock = c.get(f"/cases/{case_id}/clock", headers=CISO).json()
    for r in clock["regimes"]:
        if r["applies"]:
            s = r["stages"][0]
            print(f"   {r['name']:<38} {s['label']}: {fmt(s['seconds_remaining'] or 0)} left")

    say("7. DRAFT", f"{story['regime']} early warning")
    stage = "early_warning" if story["regime"] != "gdpr" else "notification"
    d = c.post(f"/cases/{case_id}/reports", json={"regime": story["regime"], "stage": stage},
               headers=CISO).json()
    for f in d["fields"]:
        print(f"   {f['label'][:44]:<44} {str(f['value'])[:70]}")
    print(f"   completeness {d['completeness']:.0%}, every field linked to evidence")

    say("8. APPROVE", "AI requests submission; humans decide")
    req = c.post(f"/cases/{case_id}/actions", headers=AI, json={
        "action": "submit_report", "params": {"regime": story["regime"], "stage": stage, "draft_id": d["draft_id"]},
        "rationale": "draft complete"}).json()
    print(f"   requested by AI, needs {req['required_roles']}")
    ai_try = c.post(f"/actions/{req['id']}/decide", headers={**AI, "X-Roles": "ciso"},
                    json={"decision": "approve", "role": "ciso"})
    print(f"   AI tries to approve itself -> HTTP {ai_try.status_code}: {ai_try.json()['detail']}")
    c.post(f"/actions/{req['id']}/decide", headers=CISO, json={"decision": "approve", "role": "ciso"})
    r = c.post(f"/actions/{req['id']}/decide", headers=MGMT, json={"decision": "approve", "role": "management"}).json()
    print(f"   CISO + management approve -> {r['status']}")
    r = c.post(f"/actions/{req['id']}/execute", headers=CISO).json()
    print(f"   executed: {r['result']}")
    elapsed = time.perf_counter() - t_start

    say("9. VERIFY", "tamper-evident audit log")
    v = c.get("/audit/verify", headers=CISO).json()
    print(f"   chain ok={v['ok']}  entries={v['entries']}  head={v['head_hash'][:16]}...")
    with app.state.engine.begin() as conn:
        conn.execute(text("UPDATE vartija_audit_log SET payload = :p WHERE seq = 3"),
                      {"p": '{"note": "nothing happened here"}'})
    v = c.get("/audit/verify", headers=CISO).json()
    print(f"   after a direct DB edit: ok={v['ok']}  first broken entry={v['first_broken_seq']} ({v['reason']})")

    say("DONE", f"detection to approved, recorded report: {elapsed:.2f} s of machine time "
                "(on stage, add the humans' minutes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
