"""Event intake from ARCC-X (or any signal source).

Validates the schema, de-duplicates by ``event_id``, and opens or extends a case by
``correlation_id``. Signature checking happens in the API layer before this runs.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from . import audit
from .models import Case, Event, as_utc
from .redact import redact_text

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}


class EventIn(BaseModel):
    """The contract between ARCC-X and Vartija. Keep it small and versioned."""

    event_id: str = Field(min_length=8, max_length=128)
    schema_version: str = "1.0"
    source: str = Field(max_length=64)                 # e.g. "arcc-x"
    event_type: str = Field(max_length=64)             # e.g. "auth.credential_stuffing"
    occurred_at: datetime
    detected_at: datetime | None = None                # when a human/system became aware; defaults to occurred_at
    correlation_id: str = Field(max_length=128)        # groups events into one case
    asset_id: str | None = Field(default=None, max_length=128)
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)              # kept separate from severity on purpose
    summary: str = Field(max_length=2000)
    attributes: dict = Field(default_factory=dict)     # e.g. users_affected, cross_border, iocs
    evidence_refs: list[str] = Field(default_factory=list)  # pointers to logs, never the logs themselves
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"

    @field_validator("schema_version")
    @classmethod
    def _known_version(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported schema_version {v}")
        return v

    @field_validator("occurred_at", "detected_at")
    @classmethod
    def _tz_aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return v


def ingest(session: Session, event: EventIn, raw_body: bytes, *, sector: str) -> tuple[Case, bool]:
    """Returns (case, created_new_event). A duplicate event_id returns the existing case."""
    existing = session.get(Event, event.event_id)
    if existing is not None:
        return session.get(Case, existing.case_id), False

    detected = event.detected_at or event.occurred_at
    case = session.query(Case).filter_by(correlation_id=event.correlation_id).one_or_none()
    if case is None:
        case = Case(correlation_id=event.correlation_id, title=redact_text(event.summary)[:300],
                    asset_id=event.asset_id, sector=sector, detected_at=detected, flags={}, milestones={})
        session.add(case)
        session.flush()
        audit.append(session, action="case.opened", actor=event.source, actor_kind="system", case_id=case.id,
                     payload={"correlation_id": event.correlation_id, "detected_at": detected.isoformat(),
                              "first_event": event.event_id})
    elif detected < as_utc(case.detected_at):
        # Awareness is the EARLIEST detection: a late-arriving earlier event moves the clock back, loudly.
        audit.append(session, action="case.detected_at_moved", actor=event.source, actor_kind="system",
                     case_id=case.id, payload={"from": as_utc(case.detected_at).isoformat(),
                                               "to": detected.isoformat(), "event_id": event.event_id})
        case.detected_at = detected

    digest = hashlib.sha256(raw_body).hexdigest()
    session.add(Event(
        event_id=event.event_id, case_id=case.id, schema_version=event.schema_version, source=event.source,
        event_type=event.event_type, occurred_at=event.occurred_at, severity=event.severity,
        confidence=event.confidence, summary=event.summary, attributes=event.attributes,
        evidence_refs=event.evidence_refs, payload_sha256=digest,
    ))
    session.flush()
    audit.append(session, action="event.received", actor=event.source, actor_kind="system", case_id=case.id,
                 payload={"event_id": event.event_id, "type": event.event_type, "severity": event.severity,
                          "confidence": event.confidence, "payload_sha256": digest,
                          "evidence_refs": event.evidence_refs})
    return case, True
