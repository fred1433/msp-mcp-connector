"""Test harness: a throwaway signing key standing in for the MSP's identity provider,
the connector served over real HTTP (uvicorn on a free port), and a minimal MCP
JSON-RPC client so every test crosses the MCP HTTP boundary."""

from __future__ import annotations

import base64
import json
import shutil
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from handover.audit import AuditLog
from handover.config import Budgets, Settings
from handover.server import App, build
from fakes import FixtureTransport

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://login.example-idp.test/msp-tenant/v2.0"
FIXED_TIME = "2026-10-09T14:00:00+00:00"


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode().rstrip("=")


class TestIdP:
    __test__ = False
    """Signs tokens like the MSP's identity provider would. Test only."""

    def __init__(self, kid: str = "test-key-1") -> None:
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = self.key.public_key().public_numbers()
        self.jwks = {"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64(pub.n), "e": _b64(pub.e)}]}

    def token(self, sub: str, *, aud: str, iss: str = ISSUER, ttl: int = 600, key=None, kid=None) -> str:
        now = int(time.time())
        claims = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl, "azp": "claude-connector"}
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": kid or self.kid})


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Running:
    app: App
    url: str
    resource: str
    idp: TestIdP
    transport: FixtureTransport
    policy_path: Path
    server: uvicorn.Server
    sleeps: list = field(default_factory=list)

    def token(self, who: str, **kw) -> str:
        return self.idp.token(who, aud=self.resource, **kw)

    def stop(self) -> None:
        self.server.should_exit = True


def start(tmp: Path, *, budgets: Budgets | None = None, scenario: str = "default",
          site_summary_type_id: int | None = 41, fixtures: Path | None = None) -> Running:
    port = free_port()
    resource = f"http://127.0.0.1:{port}/mcp"
    policy_path = tmp / "policy.json"
    shutil.copy(ROOT / "config" / "policy.example.json", policy_path)
    idp = TestIdP()
    transport = FixtureTransport(fixtures or ROOT / "fixtures", scenario=scenario)
    sleeps: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    settings = Settings(
        resource_url=resource, issuer=ISSUER, audience=resource, jwks_url=None, jwks_file=None,
        policy_file=policy_path, credentials_file=ROOT / "config" / "psa-credentials.example.json",
        audit_file=tmp / "audit.jsonl", cursor_secret=b"test-cursor-secret-0123456789",
        itglue_region="us", itglue_api_key="ITG.synthetic-demo-key",
        connectwise_base_url="https://api-na.myconnectwise.net/v4_6_release/apis/3.0",
        connectwise_client_id="00000000-demo-client-id", budgets=budgets or Budgets(),
        itglue_site_summary_type_id=site_summary_type_id,
    )
    app = build(settings, upstream_transport=transport, jwks=idp.jwks, audit=AuditLog(tmp / "audit.jsonl"),
                sleep=fake_sleep, clock_iso=lambda: FIXED_TIME)
    server = uvicorn.Server(uvicorn.Config(app.asgi(), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return Running(app=app, url=resource, resource=resource, idp=idp, transport=transport,
                   policy_path=policy_path, server=server, sleeps=sleeps)


class McpSession:
    """Minimal MCP client over Streamable HTTP (JSON response mode)."""

    PROTOCOL = "2025-06-18"

    def __init__(self, url: str, token: str | None) -> None:
        self.url = url
        self.token = token
        self.session_id: str | None = None
        self._id = 0
        self.http = httpx.Client(timeout=30)
        self.log: list[dict] = []

    def headers(self) -> dict:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": self.PROTOCOL}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def post(self, payload: dict) -> httpx.Response:
        return self.http.post(self.url, json=payload, headers=self.headers())

    def rpc(self, method: str, params: dict | None = None) -> httpx.Response:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            payload["params"] = params
        resp = self.post(payload)
        self.log.append({"request": payload, "status": resp.status_code,
                         "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text})
        return resp

    def initialize(self) -> httpx.Response:
        r = self.rpc("initialize", {"protocolVersion": self.PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "acceptance-tests", "version": "1"}})
        if r.status_code == 200:
            self.session_id = r.headers.get("mcp-session-id")
            self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def call(self, tool: str, **arguments) -> dict:
        r = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        r.raise_for_status()
        body = r.json()
        result = body["result"]
        if result.get("structuredContent") is not None:
            return result["structuredContent"]
        return json.loads(result["content"][0]["text"])
