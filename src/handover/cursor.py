"""Opaque pagination cursors bound to (principal, client, tool, query).

A cursor minted for one user, client or query is refused for any other.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from .policy import PolicyError


class CursorCodec:
    def __init__(self, secret: bytes, ttl_s: int = 900) -> None:
        if len(secret) < 16:
            raise ValueError("cursor secret must be at least 16 bytes")
        self.secret = secret
        self.ttl_s = ttl_s

    def _sig(self, body: bytes) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.secret, body, hashlib.sha256).digest()[:16]).decode().rstrip("=")

    def encode(self, *, principal: str, client_ref: str, tool: str, query: str, state: dict) -> str:
        payload = {"p": principal, "c": client_ref, "t": tool, "q": query, "s": state, "x": int(time.time()) + self.ttl_s}
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + self._sig(body)

    def decode(self, cursor: str, *, principal: str, client_ref: str, tool: str, query: str) -> dict:
        try:
            b64, sig = cursor.split(".", 1)
            body = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        except ValueError as exc:
            raise PolicyError("invalid_cursor", "This cursor is malformed.") from exc
        if not hmac.compare_digest(sig, self._sig(body)):
            raise PolicyError("invalid_cursor", "This cursor was not issued by this server.")
        payload = json.loads(body)
        if payload["x"] < time.time():
            raise PolicyError("invalid_cursor", "This cursor has expired; start the listing again.")
        if (payload["p"], payload["c"], payload["t"], payload["q"]) != (principal, client_ref, tool, query):
            raise PolicyError("invalid_cursor", "This cursor belongs to another user, client or query.")
        return payload["s"]
