"""Bearer-token authentication to replace the demo X-User headers.

    VARTIJA_AUTH=jwt VARTIJA_JWT_SECRET=<same secret CyberGRC-AI signs with>

Verifies HS256 JWTs with the standard library only (no extra dependency): signature,
``exp`` and ``nbf``. Claim names are configurable because every app names them
differently (``sub`` / ``username``, ``roles`` / ``role``). A token whose ``kind`` claim
is ``ai`` (a service token for an agent) gets an AI principal, which policy never lets
approve anything. For RS256 or an identity provider, write a dependency with PyJWT and
override ``current_principal`` the same way.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import Header, HTTPException


class TokenError(Exception):
    pass


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(secret: str, claims: dict, ttl_seconds: int = 3600) -> str:
    """For tests and local development. Production tokens come from the host app's login."""
    now = int(time.time())
    body = {"iat": now, "exp": now + ttl_seconds, **claims}
    head = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    pay = _b64e(json.dumps(body, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(secret.encode(), f"{head}.{pay}".encode(), hashlib.sha256).digest())
    return f"{head}.{pay}.{sig}"


def decode_token(secret: str, token: str, leeway: int = 30) -> dict:
    try:
        head_b, pay_b, sig_b = token.split(".")
        header = json.loads(_b64d(head_b))
        claims = json.loads(_b64d(pay_b))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError("malformed token") from exc
    if header.get("alg") != "HS256":
        raise TokenError("only HS256 tokens are accepted")
    expected = hmac.new(secret.encode(), f"{head_b}.{pay_b}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64d(sig_b)):
        raise TokenError("bad signature")
    now = time.time()
    if "exp" in claims and now > float(claims["exp"]) + leeway:
        raise TokenError("token expired")
    if "nbf" in claims and now + leeway < float(claims["nbf"]):
        raise TokenError("token not yet valid")
    return claims


def jwt_principal_dependency(secret: str, principal_cls, user_claim: str = "sub", roles_claim: str = "roles"):
    if not secret:
        raise ValueError("VARTIJA_AUTH=jwt needs VARTIJA_JWT_SECRET")

    def principal(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer token")
        try:
            claims = decode_token(secret, authorization.split(" ", 1)[1].strip())
        except TokenError as exc:
            raise HTTPException(401, f"invalid token: {exc}") from exc
        user = claims.get(user_claim)
        if not user:
            raise HTTPException(401, f"token has no '{user_claim}' claim")
        roles = claims.get(roles_claim, [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.replace(";", ",").split(",") if r.strip()]
        kind = claims.get("kind", "human")
        if kind not in {"human", "ai", "system"}:
            kind = "human"
        return principal_cls(str(user), kind, [str(r).strip().lower().replace(" ", "_") for r in roles])

    return principal
