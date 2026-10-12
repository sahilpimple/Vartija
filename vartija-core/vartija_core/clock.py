"""The regulatory clock: which reports are due, by when, and how much time is left.

Deadlines are anchored to a milestone on the case:
  * ``detected``            -> case.detected_at (when the organisation became aware)
  * ``<stage>``             -> when that stage of the same regime was completed
  * ``corrective_measure``  -> when a fix became available (milestone "corrective_measure")
If the anchor has not happened yet, the deadline is reported as ``waiting``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .config import Config
from .models import Case, as_utc

DUE_SOON_HOURS = 6


def _milestone(case: Case, key: str) -> datetime | None:
    value = (case.milestones or {}).get(key)
    if not value:
        return None
    return as_utc(datetime.fromisoformat(value))


def compute_clock(case: Case, config: Config, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    flags = case.flags or {}
    detected = as_utc(case.detected_at)
    regimes_out = []
    for regime in config.regimes_for(case.sector):
        # Before anyone has confirmed the flags, every in-scope regime *might* apply, so its
        # clock runs anyway: the 24 h starts at detection, not at the end of the analysis.
        applies: bool | None = None if not flags else bool(flags.get(regime.applies_when_flag))
        counting = applies is not False
        stages = []
        for d in regime.deadlines:
            if d.anchor == "detected":
                anchor_time = detected
            elif d.anchor == "corrective_measure":
                anchor_time = _milestone(case, "corrective_measure")
            else:
                anchor_time = _milestone(case, f"{regime.id}:{d.anchor}")
            done_at = _milestone(case, f"{regime.id}:{d.stage}")
            if done_at is not None:
                due = anchor_time + timedelta(hours=d.hours) if anchor_time else None
                status = "done" if (due is None or done_at <= due) else "done_late"
                remaining = None
            elif anchor_time is None:
                due, status, remaining = None, "waiting", None
            else:
                due = anchor_time + timedelta(hours=d.hours)
                remaining = (due - now).total_seconds()
                if remaining < 0:
                    status = "overdue"
                elif remaining < DUE_SOON_HOURS * 3600:
                    status = "due_soon"
                else:
                    status = "running"
            stages.append({
                "stage": d.stage, "label": d.label, "hours": d.hours, "anchor": d.anchor,
                "due_at": due.isoformat() if due else None,
                "seconds_remaining": int(remaining) if remaining is not None else None,
                "completed_at": done_at.isoformat() if done_at else None,
                "status": status if counting else "not_applicable",
            })
        regimes_out.append({
            "regime": regime.id, "name": regime.name, "authority": regime.authority,
            "applies": applies, "decided_by_flag": regime.applies_when_flag, "stages": stages,
        })

    # The single most urgent open deadline drives the big countdown on screen.
    open_stages = [
        (s["seconds_remaining"], r["regime"], s)
        for r in regimes_out if r["applies"] is not False
        for s in r["stages"] if s["seconds_remaining"] is not None and s["status"] != "not_applicable"
    ]
    next_due = None
    if open_stages:
        secs, regime_id, stage = min(open_stages, key=lambda t: t[0])
        next_due = {"regime": regime_id, "stage": stage["stage"], "label": stage["label"],
                    "due_at": stage["due_at"], "seconds_remaining": secs, "status": stage["status"]}
    return {
        "case_id": case.id, "now": now.isoformat(), "detected_at": detected.isoformat(),
        "next_due": next_due, "regimes": regimes_out,
        "undetermined": not flags,  # no assessment yet: every regime might apply
    }
