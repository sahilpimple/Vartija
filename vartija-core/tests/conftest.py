from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vartija_core.api import create_app  # noqa: E402
from vartija_core.client import encode  # noqa: E402
from vartija_core.security import sign  # noqa: E402
from vartija_core.settings import Settings  # noqa: E402

SECRET = "test-secret"
CISO = {"X-User": "aino", "X-Roles": "ciso"}
MGMT = {"X-User": "pekka", "X-Roles": "management"}
SOC = {"X-User": "mikko", "X-Roles": "soc_lead"}
AI = {"X-User": "triage-agent", "X-User-Kind": "ai", "X-Roles": "ciso,management"}


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(database_url=f"sqlite:///{tmp_path / 'test.db'}", event_secret=SECRET,
                config_dir=ROOT / "config", corpus_dir=ROOT / "corpus", seed_dir=ROOT / "seed",
                sector="telecom", llm_backend="rules", upload_dir=tmp_path / "data")
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def client(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app) as c:
        c.app_ref = app
        yield c


def event(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}", "schema_version": "1.0", "source": "arcc-x",
        "event_type": "auth.credential_stuffing", "occurred_at": (now - timedelta(minutes=5)).isoformat(),
        "correlation_id": "case-portal-1", "asset_id": "web-portal-01", "severity": "high", "confidence": 0.9,
        "summary": "Credential stuffing; 4200 customer accounts accessed. Contact jane.doe@example.com",
        "attributes": {"users_affected": 4200, "malicious": True, "cross_border": True, "personal_data": True,
                       "iocs": ["185.220.101.0/24"]},
        "evidence_refs": ["s3://evidence/portal/auth-2026-11-07.log#L1200-1450"],
    }
    base.update(overrides)
    return base


def post_event(client: TestClient, ev: dict, secret: str = SECRET, timestamp: int | None = None):
    body = encode(ev)
    return client.post("/events", content=body, headers={"Content-Type": "application/json",
                                                         **sign(secret, body, timestamp)})

