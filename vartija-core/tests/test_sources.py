"""Uploading challenge documents and data packs from the dashboard."""

from fastapi.testclient import TestClient

from vartija_core.api import create_app
from tests.conftest import AI, CISO, MGMT, make_settings

RULES = b"""Sample Ship Rules 2026
Regulation 9 Fire integrity
9.2 Insulation
Bulkheads between galley and stairway shall be A-60, not less than 60 min. See Regulation 9.
9.3 Doors
Doors shall be self-closing.
"""


def _c(tmp_path):
    return TestClient(create_app(make_settings(tmp_path)))


def test_upload_document_becomes_citable(tmp_path):
    with _c(tmp_path) as c:
        before = c.get("/health").json()["corpus_chunks"]
        r = c.post("/sources", headers=CISO, files={"file": ("ship-rules.md", RULES, "text/markdown")},
                   data={"prefix": "ssr"})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["kind"] == "document" and d["prefix"] == "ssr" and "ssr:9.2" in d["sample_ids"]
        assert c.get("/health").json()["corpus_chunks"] == before + d["paragraphs"]
        listed = c.get("/sources", headers=CISO).json()
        assert listed["uploaded"][0]["name"] == "ship-rules.md"
        assert (tmp_path / "data" / "corpus" / "ssr.md").exists()
        trail = c.get("/audit/verify", headers=CISO).json()
        assert trail["ok"] and trail["entries"] == 1


def test_upload_data_file_kept_as_evidence(tmp_path):
    with _c(tmp_path) as c:
        d = c.post("/sources", headers=CISO, files={"file": ("pack.csv", b"a,b\n1,2\n", "text/csv")}).json()
        assert d["kind"] == "data" and len(d["sha256"]) == 64
        assert (tmp_path / "data" / "originals" / "pack.csv").read_bytes() == b"a,b\n1,2\n"


def test_rejections(tmp_path):
    with _c(tmp_path) as c:
        up = lambda name, body=b"x", h=CISO, **kw: c.post("/sources", headers=h, files={"file": (name, body)}, **kw)  # noqa: E731
        assert up("evil.exe").status_code == 400                                  # unknown type
        assert up("empty.md", b"").status_code == 400
        assert up("rules.md", RULES, data={"prefix": "nis2"}).status_code == 400  # clashes with built-in corpus
        assert up("rules.md", RULES, h=MGMT).status_code == 403                    # executive view only
        assert up("rules.md", RULES, h=AI).status_code == 403                      # agents can't add sources
        r = up("../../outside.md", RULES)
        assert r.status_code == 200 and r.json()["name"] == "outside.md"          # path stripped
        assert not (tmp_path / "outside.md").exists()
        assert up("outside.md", RULES).status_code == 400                          # already uploaded


def test_delete_removes_from_corpus(tmp_path):
    with _c(tmp_path) as c:
        base = c.get("/health").json()["corpus_chunks"]
        c.post("/sources", headers=CISO, files={"file": ("r.md", RULES)}, data={"prefix": "r1"})
        assert c.delete("/sources/r.md", headers=CISO).json()["corpus_chunks"] == base
        assert not (tmp_path / "data" / "corpus" / "r1.md").exists()
        assert c.delete("/sources/r.md", headers=CISO).status_code == 404


def test_uploads_survive_restart(tmp_path):
    with _c(tmp_path) as c:
        n = c.post("/sources", headers=CISO, files={"file": ("r.md", RULES)}, data={"prefix": "keep"}).json()["corpus_chunks"]
    with _c(tmp_path) as c2:
        assert c2.get("/health").json()["corpus_chunks"] == n
