from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vartija_core.clock import compute_clock
from vartija_core.config import ConfigError, load_config
from vartija_core.models import Case
from vartija_core.rag import Retriever, load_corpus
from vartija_core.security import SignatureError, sign, verify

ROOT = Path(__file__).resolve().parent.parent
CONFIG = load_config(ROOT / "config")


def test_all_sectors_load_and_reference_known_regimes():
    assert {"telecom", "energy", "maritime", "industrial"} <= set(CONFIG.sectors)
    for sector in CONFIG.sectors.values():
        for regime in CONFIG.regimes_for(sector.id):
            assert regime.report_templates, regime.id
    with pytest.raises(ConfigError):
        CONFIG.sector("bakery")


def test_signature_verification():
    body = b'{"a":1}'
    h = sign("s", body, timestamp=1_000_000)
    verify("s", body, h["X-Vartija-Timestamp"], h["X-Vartija-Signature"], now=1_000_010)
    with pytest.raises(SignatureError):
        verify("s", b'{"a":2}', h["X-Vartija-Timestamp"], h["X-Vartija-Signature"], now=1_000_010)
    with pytest.raises(SignatureError):  # timestamp swapped -> signature no longer matches
        verify("s", body, "1000005", h["X-Vartija-Signature"], now=1_000_010)


def _case(**kw) -> Case:
    base = dict(id="c1", correlation_id="c1", title="t", sector="industrial",
                detected_at=datetime(2026, 11, 7, 10, tzinfo=timezone.utc), flags={}, milestones={})
    base.update(kw)
    return Case(**base)


def test_clock_statuses_and_anchors():
    t0 = datetime(2026, 11, 7, 10, tzinfo=timezone.utc)
    case = _case(flags={"cra_reportable": True, "nis2_significant": False, "personal_data_breach": False})

    c = compute_clock(case, CONFIG, now=t0 + timedelta(hours=20))
    cra = next(r for r in c["regimes"] if r["regime"] == "cra")
    stages = {s["stage"]: s for s in cra["stages"]}
    assert stages["early_warning"]["status"] == "due_soon"
    assert stages["notification"]["status"] == "running"
    assert stages["final_report"]["status"] == "waiting"  # no fix available yet
    assert c["next_due"] == {**c["next_due"], "regime": "cra", "stage": "early_warning"}
    nis2 = next(r for r in c["regimes"] if r["regime"] == "nis2_fi")
    assert all(s["status"] == "not_applicable" for s in nis2["stages"])

    late = compute_clock(case, CONFIG, now=t0 + timedelta(hours=30))
    assert next(s for s in next(r for r in late["regimes"] if r["regime"] == "cra")["stages"]
                if s["stage"] == "early_warning")["status"] == "overdue"

    case.milestones = {"cra:early_warning": (t0 + timedelta(hours=26)).isoformat(),
                       "corrective_measure": (t0 + timedelta(days=3)).isoformat()}
    c = compute_clock(case, CONFIG, now=t0 + timedelta(days=4))
    stages = {s["stage"]: s for s in next(r for r in c["regimes"] if r["regime"] == "cra")["stages"]}
    assert stages["early_warning"]["status"] == "done_late"
    assert stages["final_report"]["due_at"].startswith("2026-11-24")  # 14 days after the fix


def test_retrieval_finds_the_right_law():
    r = Retriever(load_corpus(ROOT / "corpus"))
    top = r.search("actively exploited vulnerability in our product", k=3, tags={"cra"})
    assert top and top[0][0].id.startswith("cra:art14")
    top = r.search("when is an incident significant severe disruption financial loss", k=2, tags={"nis2"})
    assert top[0][0].id == "nis2:art23-3"
