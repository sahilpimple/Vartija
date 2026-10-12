"""Sender helper for ARCC-X (or any signal source).

    from vartija_core.client import send_event
    send_event("http://localhost:8000/events", secret, {...event dict...})

Uses a fresh timestamp per attempt and the same ``event_id`` on retries, so a retry
after a timeout can never create a duplicate case.
"""

from __future__ import annotations

import json
import time

import httpx

from .security import sign


def encode(event: dict) -> bytes:
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def send_event(url: str, secret: str, event: dict, *, retries: int = 3, timeout: float = 10.0,
               client: httpx.Client | None = None) -> dict:
    body = encode(event)
    http = client or httpx.Client(timeout=timeout)
    last_error: Exception | None = None
    for attempt in range(retries):
        headers = {"Content-Type": "application/json", **sign(secret, body)}
        try:
            r = http.post(url, content=body, headers=headers)
            if r.status_code < 500:
                r.raise_for_status()  # 4xx is our bug, not worth retrying
                return r.json()
            last_error = httpx.HTTPStatusError(f"server error {r.status_code}", request=r.request, response=r)
        except httpx.TransportError as exc:
            last_error = exc
        time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f"event {event.get('event_id')} not delivered after {retries} attempts: {last_error}")
