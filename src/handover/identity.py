"""Who is calling.

The principal is the pair (iss, sub) of a validated access token. Nothing else
grants access: not an e-mail claim, not a display name, not a tool argument.

Token validation uses PyJWT (signature, exp, iss, aud). This module does not
issue tokens: the MSP's existing identity provider does (see docs/claude-admin.md).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import jwt
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.middleware.auth_context import get_access_token


@dataclass(frozen=True)
class Principal:
    iss: str
    sub: str

    @property
    def key(self) -> str:
        return f"{self.iss}|{self.sub}"


class JwtVerifier:
    """TokenVerifier for the MCP SDK bearer middleware.

    `is_authorized` is consulted on every HTTP request, after the signature
    check, so a principal removed or disabled in the policy is refused at the
    next request (401), even inside an existing MCP session.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        resource_url: str,
        jwks_url: str | None = None,
        jwks: dict | None = None,
        is_authorized: Callable[[Principal], bool],
        algorithms: tuple[str, ...] = ("RS256", "ES256"),
        leeway_s: int = 30,
    ) -> None:
        if not jwks_url and not jwks:
            raise ValueError("a JWKS URL or a JWKS document is required")
        self.issuer = issuer
        self.audience = audience
        self.resource_url = resource_url
        self.algorithms = list(algorithms)
        self.leeway_s = leeway_s
        self.is_authorized = is_authorized
        self._jwk_client = jwt.PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None
        self._jwks = jwt.PyJWKSet.from_dict(jwks) if jwks else None

    @classmethod
    def jwks_from_file(cls, path: Path) -> dict:
        return json.loads(Path(path).read_text())

    def _signing_key(self, token: str):
        if self._jwk_client is not None:
            return self._jwk_client.get_signing_key_from_jwt(token).key
        kid = jwt.get_unverified_header(token).get("kid")
        for key in self._jwks.keys:  # type: ignore[union-attr]
            if key.key_id == kid:
                return key.key
        raise jwt.InvalidTokenError("unknown key id")

    def _decode(self, token: str) -> dict:
        key = self._signing_key(token)
        return jwt.decode(
            token,
            key,
            algorithms=self.algorithms,
            audience=self.audience,
            issuer=self.issuer,
            leeway=self.leeway_s,
            options={"require": ["exp", "iss", "sub", "aud"]},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = await asyncio.to_thread(self._decode, token)
        except (jwt.PyJWTError, jwt.PyJWKClientError, ValueError):
            return None
        principal = Principal(iss=str(claims["iss"]), sub=str(claims["sub"]))
        if not self.is_authorized(principal):
            return None
        scope = claims.get("scope") or claims.get("scp") or ""
        scopes = scope.split() if isinstance(scope, str) else list(scope)
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or "unknown-client"),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self.resource_url,
            subject=principal.sub,
            claims={"iss": principal.iss},
        )


def current_principal() -> Principal | None:
    token = get_access_token()
    if token is None or not token.subject or not token.claims or not token.claims.get("iss"):
        return None
    return Principal(iss=str(token.claims["iss"]), sub=token.subject)
