"""Data model.

A *case* groups related *events* (by correlation ID). Assessments, action requests,
approvals and report drafts hang off the case. Every state change is also written
to the hash-chained ``AuditEntry`` table (see ``audit.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; treat naive datetimes from the DB as UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Case(Base):
    __tablename__ = "vartija_cases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    correlation_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(300))
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sector: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | reported | closed
    # The legal clocks run from when the organisation became aware of the incident.
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Set by the significance assessment, e.g. {"nis2_significant": true}.
    flags: Mapped[dict] = mapped_column(JSON, default=dict)
    # Stage completions, e.g. {"nis2_fi:early_warning": "2026-11-07T10:00:00+00:00"}.
    milestones: Mapped[dict] = mapped_column(JSON, default=dict)

    events: Mapped[list[Event]] = relationship(back_populates="case", order_by="Event.received_at")
    assessments: Mapped[list[Assessment]] = relationship(back_populates="case", order_by="Assessment.created_at")


class Event(Base):
    __tablename__ = "vartija_events"

    # The sender's event ID doubles as the idempotency key: a resend is a no-op.
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("vartija_cases.id"), index=True)
    schema_version: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    summary: Mapped[str] = mapped_column(Text)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    payload_sha256: Mapped[str] = mapped_column(String(64))

    case: Mapped[Case] = relationship(back_populates="events")


class Assessment(Base):
    __tablename__ = "vartija_assessments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("vartija_cases.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    engine: Mapped[str] = mapped_column(String(64))  # "rules" or "ollama:llama3.1" etc.
    prompt_version: Mapped[str] = mapped_column(String(64))
    flags: Mapped[dict] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    rationale: Mapped[str] = mapped_column(Text)
    citations: Mapped[list] = mapped_column(JSON, default=list)
    # Citations the model produced that were NOT in the retrieved context. Never trusted.
    rejected_citations: Mapped[list] = mapped_column(JSON, default=list)
    conflicts: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    needs_human_review: Mapped[bool] = mapped_column(default=True)

    case: Mapped[Case] = relationship(back_populates="assessments")


class ActionRequest(Base):
    __tablename__ = "vartija_action_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("vartija_cases.id"), index=True)
    action: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(128))
    requested_by_kind: Mapped[str] = mapped_column(String(16))  # human | ai | system
    rationale: Mapped[str] = mapped_column(Text, default="")
    # pending_approval | approved | rejected | executed | failed
    status: Mapped[str] = mapped_column(String(32))
    required_roles: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class Approval(Base):
    __tablename__ = "vartija_approvals"
    __table_args__ = (UniqueConstraint("request_id", "approver", name="uq_one_vote_per_approver"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("vartija_action_requests.id"), index=True)
    approver: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))  # approve | reject
    comment: Mapped[str] = mapped_column(Text, default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportDraft(Base):
    __tablename__ = "vartija_report_drafts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("vartija_cases.id"), index=True)
    regime: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(64))
    language: Mapped[str] = mapped_column(String(8), default="en")
    fields: Mapped[list] = mapped_column(JSON)  # [{key,label,value,evidence,source,filled}]
    completeness: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEntry(Base):
    __tablename__ = "vartija_audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[str] = mapped_column(String(40))  # ISO string, hashed exactly as stored
    case_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    actor: Mapped[str] = mapped_column(String(128))
    actor_kind: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)
