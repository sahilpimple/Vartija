"""HMAC signing for system-to-system events (ARCC-X -> Vartija).

The sender signs ``"{timestamp}.{raw_body}"`` with the shared secret and sends:

    X-Vartija-Timestamp: 1762430400
    X-Vartija-Signature: sha256=<hex digest>

Binding the timestamp into the signature stops an attacker replaying an old event
with a fresh timestamp. The event's own ``event_id`` handles duplicate delivery.
"""

from __future__ import annotations

import hashlib
import hmac
import time


class SignatureError(Exception):
    pass


def sign(secret: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(timestamp if timestamp is not None else time.time()))
    digest = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Vartija-Timestamp": ts, "X-Vartija-Signature": f"sha256={digest}"}


def verify(secret: str, body: bytes, timestamp: str | None, signature: str | None,
           max_skew_seconds: int = 300, now: float | None = None) -> None:
    if not timestamp or not signature:
        raise SignatureError("missing signature headers")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise SignatureError("bad timestamp") from exc
    current = now if now is not None else time.time()
    if abs(current - ts) > max_skew_seconds:
        raise SignatureError("timestamp outside allowed window")
    expected = sign(secret, body, ts)["X-Vartija-Signature"]
    if not hmac.compare_digest(expected, signature):
        raise SignatureError("signature mismatch")
