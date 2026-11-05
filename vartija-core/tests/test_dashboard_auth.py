"""Dashboard route, demo seed, action listing, JWT auth and embeddings fallback."""

import pytest
from fastapi.testclient import TestClient

from vartija_core.api import create_app
from vartija_core.auth_jwt import TokenError, decode_token, make_token
from vartija_core.embeddings import make_embedder
from vartija_core.rag import Chunk, HybridRetriever
from tests.conftest import CISO, MGMT, SOC, AI, make_settings


def demo_client(tmp_path, **kw):
    return TestClient(create_app(make_settings(tmp_path, demo_mode="1", **kw)))


def test_dashboard_served(client):
    r = client.get("/dashboard")
    assert r.status_code == 200 and "Regulatory clock" in r.text


def test_health_reports_new_settings(client):
    h = client.get("/health").json()
    assert {"retriever", "embeddings", "auth", "demo"} <= h.keys()
    assert h["demo"] is False  # test secret is not the dev default


def test_demo_seed_off_unless_enabled(client):
    assert client.post("/demo/seed", headers=CISO).status_code == 404


def test_demo_seed_and_full_dashboard_flow(tmp_path):
    with demo_client(tmp_path) as c:
        case_id = c.post("/demo/seed", headers=SOC).json()["case_id"]
        assert c.get(f"/cases/{case_id}", headers=CISO).json()["events"]
        a = c.post(f"/cases/{case_id}/assess", headers=CISO, json={}).json()
        c.post(f"/cases/{case_id}/flags", headers=CISO, json={"flags": a["flags"], "reason": "test confirm"})
        d = c.post(f"/cases/{case_id}/reports", headers=SOC, json={"regime": "nis2_fi", "stage": "early_warning"}).json()
        req = c.post(f"/cases/{case_id}/actions", headers=SOC,
                     json={"action": "submit_report", "params": {"regime": "nis2_fi", "stage": "early_warning",
                                                                 "draft_id": d["draft_id"]}}).json()
        listed = c.get(f"/cases/{case_id}/actions", headers=CISO).json()
        assert [x["id"] for x in listed] == [req["id"]] and listed[0]["status"] == "pending_approval"
        assert c.post(f"/actions/{req['id']}/decide", headers=AI, json={"decision": "approve", "role": "ciso"}).status_code == 403
        c.post(f"/actions/{req['id']}/decide", headers=CISO, json={"decision": "approve", "role": "ciso"})
        c.post(f"/actions/{req['id']}/decide", headers=MGMT, json={"decision": "approve", "role": "management"})
        assert c.post(f"/actions/{req['id']}/execute", headers=CISO).json()["status"] == "executed"
        assert c.get("/audit/verify", headers=CISO).json()["ok"] is True


def test_jwt_roundtrip_and_rejections():
    tok = make_token("s3cret", {"sub": "aino", "roles": ["CISO"]})
    assert decode_token("s3cret", tok)["sub"] == "aino"
    with pytest.raises(TokenError, match="bad signature"):
        decode_token("other", tok)
    with pytest.raises(TokenError, match="expired"):
        decode_token("s3cret", make_token("s3cret", {"sub": "x"}, ttl_seconds=-120))
    with pytest.raises(TokenError, match="malformed"):
        decode_token("s3cret", "not-a-token")


def test_jwt_mode_replaces_demo_headers(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, auth_mode="jwt", jwt_secret="k"))) as c:
        assert c.get("/cases", headers=CISO).status_code == 401            # demo headers no longer work
        good = {"Authorization": "Bearer " + make_token("k", {"sub": "aino", "roles": "GRC Manager, ciso"})}
        assert c.get("/cases", headers=good).status_code == 200
        bad = {"Authorization": "Bearer " + make_token("wrong", {"sub": "aino"})}
        assert c.get("/cases", headers=bad).status_code == 401


def test_jwt_ai_token_cannot_confirm_duties(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, auth_mode="jwt", jwt_secret="k", demo_mode="1"))) as c:
        human = {"Authorization": "Bearer " + make_token("k", {"sub": "aino", "roles": ["ciso"]})}
        ai = {"Authorization": "Bearer " + make_token("k", {"sub": "agent", "roles": ["ciso"], "kind": "ai"})}
        case_id = c.post("/demo/seed", headers=human).json()["case_id"]
        r = c.post(f"/cases/{case_id}/flags", headers=ai, json={"flags": {"nis2_significant": True}, "reason": "ai try"})
        assert r.status_code == 403


def test_embedder_off_and_unreachable(tmp_path):
    assert make_embedder(make_settings(tmp_path))[0] is None
    fn, msg = make_embedder(make_settings(tmp_path, embed_backend="ollama", llm_base_url="http://127.0.0.1:9",
                                          llm_timeout_seconds=1))
    assert fn is None and "unavailable" in msg


def test_app_starts_when_embeddings_unreachable(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, embed_backend="ollama", llm_base_url="http://127.0.0.1:9",
                                             llm_timeout_seconds=1))) as c:
        assert "unavailable" in c.get("/health").json()["embeddings"]


def test_hybrid_uses_injected_embedder():
    chunks = [Chunk("a", "Doors", "fire doors", "x", ()), Chunk("b", "Ducts", "ventilation ducts", "x", ())]
    r = HybridRetriever(chunks, embed=lambda ts: [[t.count("door"), t.count("duct")] for t in ts])
    assert r.search("door", k=1)[0][0].id == "a"
