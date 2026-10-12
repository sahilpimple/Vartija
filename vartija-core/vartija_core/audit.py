"""Hash-chained, tamper-evident audit log.

Each entry stores ``entry_hash = sha256(prev_hash || canonical_json(entry))``. Changing,
deleting or re-ordering any stored row breaks every hash after it, and ``verify_chain``
reports the first broken sequence number. This proves tampering *happened*; it does not
prevent it. For production, also anchor the latest hash somewhere the database admin
cannot write (a signed timestamp service, a second system, or a printed report).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEntry, utcnow

GENESIS_HASH = "0" * 64
_append_lock = threading.Lock()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_hash(prev_hash: str, seq: int, ts: str, case_id: str | None, actor: str,
                 actor_kind: str, action: str, payload: dict) -> str:
    body = canonical_json({
        "seq": seq, "ts": ts, "case_id": case_id, "actor": actor,
        "actor_kind": actor_kind, "action": action, "payload": payload,
    })
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def append(session: Session, *, action: str, actor: str, actor_kind: str = "system",
           case_id: str | None = None, payload: dict | None = None) -> AuditEntry:
    """Append one entry. Call inside the same transaction as the change it records."""
    payload = json.loads(canonical_json(payload or {}))  # normalise to what the DB will return
    with _append_lock:
        query = select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)
        if session.get_bind().dialect.name == "postgresql":
            query = query.with_for_update()
        last = session.scalars(query).first()
        seq = (last.seq + 1) if last else 1
        prev = last.entry_hash if last else GENESIS_HASH
        ts = utcnow().isoformat()
        entry = AuditEntry(
            seq=seq, ts=ts, case_id=case_id, actor=actor, actor_kind=actor_kind, action=action,
            payload=payload, prev_hash=prev,
            entry_hash=compute_hash(prev, seq, ts, case_id, actor, actor_kind, action, payload),
        )
        session.add(entry)
        session.flush()
        return entry


@dataclass
class ChainReport:
    ok: bool
    entries: int
    head_hash: str
    first_broken_seq: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def verify_chain(session: Session) -> ChainReport:
    prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    for entry in session.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
        count += 1
        if entry.seq != expected_seq:
            return ChainReport(False, count, prev, entry.seq, f"missing entry before seq {entry.seq}")
        if entry.prev_hash != prev:
            return ChainReport(False, count, prev, entry.seq, "prev_hash does not match previous entry")
        recomputed = compute_hash(prev, entry.seq, entry.ts, entry.case_id, entry.actor,
                                  entry.actor_kind, entry.action, entry.payload)
        if recomputed != entry.entry_hash:
            return ChainReport(False, count, prev, entry.seq, "entry content was modified after it was written")
        prev = entry.entry_hash
        expected_seq += 1
    return ChainReport(True, count, prev)
