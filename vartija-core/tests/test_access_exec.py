"""Role-based access to the engineer and executive views, and the executive summary."""

from fastapi.testclient import TestClient

from vartija_core.api import create_app
from tests.conftest import AI, CISO, MGMT, SOC, make_settings

CEO = {"X-User": "sanna", "X-Roles": "ceo,management"}
ADMIN = {"X-User": "ella", "X-Roles": "admin"}


def _client(tmp_path, **kw):
    return TestClient(create_app(make_settings(tmp_path, demo_mode="1", **kw)))


def test_me_reports_views(tmp_path):
    with _client(tmp_path) as c:
        assert c.get("/me", headers=CISO).json()["views"] == ["engineer"]
        assert c.get("/me", headers=MGMT).json()["views"] == ["executive"]
        assert set(c.get("/me", headers=ADMIN).json()["views"]) == {"engineer", "executive"}
        assert c.get("/me", headers=AI).json()["views"] == ["engineer"]       # agents never get the board view


def test_executive_cannot_read_engineer_data_and_vice_versa(tmp_path):
    with _client(tmp_path) as c:
        cid = c.post("/demo/seed", headers=SOC).json()["case_id"]
        assert c.get("/cases", headers=MGMT).status_code == 403
        assert c.get(f"/cases/{cid}", headers=CEO).status_code == 403
        assert c.post("/demo/seed", headers=CEO).status_code == 403
        assert c.get("/exec/summary", headers=CISO).status_code == 403
        assert c.get("/exec/summary", headers=AI).status_code == 403
        assert c.get("/exec/summary", headers=ADMIN).status_code == 200
        assert c.get("/audit/verify", headers=CEO).status_code == 200        # proof is shared


def test_exec_summary_and_signing_from_exec_view(tmp_path):
    with _client(tmp_path) as c:
        cid = c.post("/demo/seed", headers=SOC).json()["case_id"]
        a = c.post(f"/cases/{cid}/assess", headers=CISO, json={}).json()
        s0 = c.get("/exec/summary", headers=CEO).json()
        assert any("not yet confirmed" in r["text"] for r in s0["risks"])     # AI flag awaiting a human
        assert s0["value"]["counts"]["assessment.created"] == 1
        c.post(f"/cases/{cid}/flags", headers=CISO, json={"flags": a["flags"], "reason": "confirm"})
        d = c.post(f"/cases/{cid}/reports", headers=SOC, json={"regime": "nis2_fi", "stage": "early_warning"}).json()
        req = c.post(f"/cases/{cid}/actions", headers=SOC, json={
            "action": "submit_report", "params": {"regime": "nis2_fi", "stage": "early_warning", "draft_id": d["draft_id"]}}).json()
        s1 = c.get("/exec/summary", headers=CEO).json()
        w = s1["waiting_on_you"]
        assert [x["id"] for x in w] == [req["id"]] and w[0]["your_role"] == "management"
        assert w[0]["what"] == "Submit the report to the authority"
        assert s1["level"] in {"amber", "red"} and s1["deadlines"]["open"] >= 1
        c.post(f"/actions/{req['id']}/decide", headers=CISO, json={"decision": "approve", "role": "ciso"})
        r = c.post(f"/actions/{req['id']}/decide", headers=CEO, json={"decision": "approve", "role": "management"})
        assert r.json()["status"] == "approved"
        assert c.get("/exec/summary", headers=CEO).json()["waiting_on_you"] == []
        assert c.get("/exec/summary", headers=CEO).json()["proof"]["chain_ok"] is True


def test_no_access_file_keeps_old_open_behaviour(tmp_path):
    import shutil
    from tests.conftest import ROOT
    cfg = tmp_path / "cfg"
    shutil.copytree(ROOT / "config", cfg)
    (cfg / "access.yaml").unlink()
    with TestClient(create_app(make_settings(tmp_path, config_dir=cfg))) as c:
        assert c.get("/cases", headers=MGMT).status_code == 200
        assert c.get("/exec/summary", headers=SOC).status_code == 200


def test_same_risk_on_many_cases_is_one_line_and_exports_count(tmp_path):
    with _client(tmp_path) as c:
        ids = [c.post("/demo/seed", headers=SOC).json()["case_id"] for _ in range(3)]
        for cid in ids:
            c.post(f"/cases/{cid}/assess", headers=CISO, json={})
        risks = c.get("/exec/summary", headers=CEO).json()["risks"]
        texts = [r["text"] for r in risks]
        assert len(texts) == len(set(texts))
        assert any(r["cases"] == 3 for r in risks)
        c.get(f"/cases/{ids[0]}/export", headers=CISO)
        assert c.get("/exec/summary", headers=CEO).json()["value"]["counts"]["export"] == 1
