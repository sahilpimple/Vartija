"""End-to-end: event in -> assessment -> approval -> report recorded -> audit verifies."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from conftest import AI, CISO, MGMT, SOC, event, post_event


def test_full_flow(client):
    r = post_event(client, event())
    assert r.status_code == 200, r.text
    case_id = r.json()["case_id"]

    clock = client.get(f"/cases/{case_id}/clock", headers=CISO).json()
    assert clock["undetermined"] is True
    assert clock["next_due"]["stage"] == "early_warning"  # clock runs before anyone has decided

    a = client.post(f"/cases/{case_id}/assess", json={"apply_flags": True}, headers=CISO).json()
    assert a["flags"]["nis2_significant"] and a["flags"]["personal_data_breach"]
    assert "nis2:art23-3" in a["citations"] and "gdpr:art33-1" in a["citations"]
    assert not any(c.startswith("cra:") for c in a["citations"])  # cites only what supports a verdict
    assert a["needs_human_review"] is True
    assert "submit_report" in a["recommended_actions"]

    clock = client.get(f"/cases/{case_id}/clock", headers=CISO).json()
    nis2 = next(x for x in clock["regimes"] if x["regime"] == "nis2_fi")
    assert nis2["applies"] is True
    assert 23 * 3600 < clock["next_due"]["seconds_remaining"] <= 24 * 3600

    d = client.post(f"/cases/{case_id}/reports", json={"regime": "nis2_fi", "stage": "early_warning"},
                    headers=CISO).json()
    assert d["completeness"] == 1.0
    fields = {f["key"]: f for f in d["fields"]}
    assert fields["malicious"]["value"] == "Yes" and fields["cross_border"]["value"] == "Yes"
    assert fields["summary"]["evidence"]  # every drafted field points at evidence
    assert "jane.doe@example.com" not in fields["summary"]["value"]  # data minimisation

    req = client.post(f"/cases/{case_id}/actions", headers=AI, json={
        "action": "submit_report", "params": {"regime": "nis2_fi", "stage": "early_warning", "draft_id": d["draft_id"]},
        "rationale": "early warning ready"}).json()
    assert req["status"] == "pending_approval"
    assert set(req["required_roles"]) == {"ciso", "management"}

    # The AI holds the roles in its headers but can never approve.
    assert client.post(f"/actions/{req['id']}/decide", headers=AI,
                       json={"decision": "approve", "role": "ciso"}).status_code == 403
    # Executing before approval is refused.
    assert client.post(f"/actions/{req['id']}/execute", headers=CISO).status_code == 409

    r1 = client.post(f"/actions/{req['id']}/decide", headers=CISO, json={"decision": "approve", "role": "ciso"}).json()
    assert r1["status"] == "pending_approval"  # all_of: still needs management
    r2 = client.post(f"/actions/{req['id']}/decide", headers=MGMT,
                     json={"decision": "approve", "role": "management"}).json()
    assert r2["status"] == "approved"

    done = client.post(f"/actions/{req['id']}/execute", headers=CISO).json()
    assert done["status"] == "executed"
    clock = client.get(f"/cases/{case_id}/clock", headers=CISO).json()
    ew = next(s for s in next(x for x in clock["regimes"] if x["regime"] == "nis2_fi")["stages"]
              if s["stage"] == "early_warning")
    assert ew["status"] == "done"
    assert clock["next_due"]["stage"] == "notification"

    v = client.get("/audit/verify", headers=SOC).json()
    assert v["ok"] and v["entries"] >= 8

    pack = client.get(f"/cases/{case_id}/export", headers=CISO).json()
    assert pack["chain"]["ok"] and pack["reports"] and pack["audit_trail"]


def test_tampering_is_detected(client):
    case_id = post_event(client, event()).json()["case_id"]
    client.post(f"/cases/{case_id}/assess", json={"apply_flags": True}, headers=CISO)
    assert client.get("/audit/verify", headers=CISO).json()["ok"]

    engine = client.app_ref.state.engine
    with engine.begin() as conn:
        conn.execute(text("UPDATE vartija_audit_log SET payload = :p WHERE seq = 2"),
                      {"p": '{"event_id": "forged"}'})
    v = client.get("/audit/verify", headers=CISO).json()
    assert v["ok"] is False and v["first_broken_seq"] == 2

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM vartija_audit_log WHERE seq = 1"))
    assert client.get("/audit/verify", headers=CISO).json()["ok"] is False


def test_duplicate_and_bad_signatures(client):
    ev = event()
    first = post_event(client, ev).json()
    again = post_event(client, ev).json()
    assert again == {"case_id": first["case_id"], "duplicate": True}

    assert post_event(client, event(), secret="wrong").status_code == 401
    assert post_event(client, event(), timestamp=int(time.time()) - 3600).status_code == 401
    assert client.post("/events", json=event()).status_code == 401  # unsigned


def test_correlation_groups_events_and_earliest_detection_wins(client):
    first = post_event(client, event()).json()["case_id"]
    two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0)
    earlier = event(occurred_at=two_hours_ago.isoformat(), event_type="auth.anomaly", severity="medium")
    second = post_event(client, earlier).json()["case_id"]
    assert first == second
    case = client.get(f"/cases/{first}", headers=CISO).json()
    assert datetime.fromisoformat(case["detected_at"]) == two_hours_ago
    assert len(case["events"]) == 2
    trail = client.get(f"/cases/{first}/audit", headers=CISO).json()
    assert any(t["action"] == "case.detected_at_moved" for t in trail)


def test_schema_validation(client):
    assert post_event(client, event(severity="apocalyptic")).status_code == 422
    assert post_event(client, event(confidence=1.5)).status_code == 422
    assert post_event(client, event(occurred_at="2026-11-07T10:00:00")).status_code == 422  # naive time
    assert post_event(client, event(schema_version="9.9")).status_code == 422


def test_policy_rules(client):
    case_id = post_event(client, event()).json()["case_id"]
    assert client.post(f"/cases/{case_id}/actions", headers=CISO,
                       json={"action": "delete_all_logs"}).status_code == 403  # fail closed
    note = client.post(f"/cases/{case_id}/actions", headers=CISO, json={"action": "add_note"}).json()
    assert note["status"] == "approved"  # no approval needed

    req = client.post(f"/cases/{case_id}/actions", headers=CISO, json={"action": "contain_host"}).json()
    # requester cannot self-approve
    assert client.post(f"/actions/{req['id']}/decide", headers=CISO,
                       json={"decision": "approve", "role": "ciso"}).status_code == 403
    # wrong role for this action
    assert client.post(f"/actions/{req['id']}/decide", headers=MGMT,
                       json={"decision": "approve", "role": "management"}).status_code == 403
    # role not held
    assert client.post(f"/actions/{req['id']}/decide", headers=MGMT,
                       json={"decision": "approve", "role": "soc_lead"}).status_code == 403
    rej = client.post(f"/actions/{req['id']}/decide", headers=SOC,
                      json={"decision": "reject", "role": "soc_lead", "comment": "preserve memory first"}).json()
    assert rej["status"] == "rejected"
    assert client.post(f"/actions/{req['id']}/execute", headers=SOC).status_code == 409


def test_only_humans_confirm_flags(client):
    case_id = post_event(client, event()).json()["case_id"]
    assert client.post(f"/cases/{case_id}/flags", headers=AI,
                       json={"flags": {"nis2_significant": True}, "reason": "model said so"}).status_code == 403
    ok = client.post(f"/cases/{case_id}/flags", headers=CISO,
                     json={"flags": {"nis2_significant": False}, "reason": "only 3 test accounts"})
    assert ok.status_code == 200
    clock = client.get(f"/cases/{case_id}/clock", headers=CISO).json()
    assert all(r["applies"] is False for r in clock["regimes"])
    assert clock["next_due"] is None


def test_conflicts_surface(client):
    ev = event(event_type="malware.ransomware", summary="Ransomware on billing server", severity="critical",
               attributes={"users_affected": 5000, "malicious": True})
    case_id = post_event(client, ev).json()["case_id"]
    a = client.post(f"/cases/{case_id}/assess", json={}, headers=CISO).json()
    assert "contain_host" in a["recommended_actions"]
    assert any(c["id"] == "contain_vs_evidence" for c in a["conflicts"])
