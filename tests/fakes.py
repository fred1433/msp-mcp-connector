"""Per-endpoint fixtures for ConnectWise PSA and IT Glue.

This is not an emulator. Each fixture file describes exactly one request the
connector makes and the response it gets, with the provenance of that shape:
"verified" (vendor documentation), "third-party" (a public implementation,
linked) or "assumption". See docs/api-assumptions.md.

The matcher is stricter than the real APIs on purpose:
- a request with a query parameter the fixture does not list is rejected;
- `conditions=` must match the grammar the connector generates;
- auth headers must have the documented shape and name a known synthetic credential;
- a request with no fixture is a violation, recorded and surfaced by the tests.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import httpx

CW_HOST = "api-na.myconnectwise.net"
ITG_HOST = "api.itglue.com"

# The only conditions the connector generates (see handover/connectwise.py).
CONDITIONS_GRAMMAR = re.compile(r"^company/id=\d+ and closedFlag=false$")

SYNTHETIC_PSA = {  # base64 of companyId+publicKey:privateKey, synthetic values from config/psa-credentials.example.json
    "alice": "msp_demo+pubAliceDEMO0001:privAliceDEMO0001",
    "bob": "msp_demo+pubBobDEMO00002:privBobDEMO00002",
}


class FixtureTransport(httpx.AsyncBaseTransport):
    def __init__(self, root: Path, scenario: str = "default") -> None:
        self.scenario = scenario
        self.fixtures: list[dict] = []
        for path in sorted(Path(root).rglob("*.json")):
            fx = json.loads(path.read_text())
            fx["_file"] = str(path.relative_to(root))
            fx["_served"] = 0
            self.fixtures.append(fx)
        self.violations: list[str] = []
        self.requests: list[dict] = []

    # ---------------------------------------------------------------- checks
    def _psa_identity(self, request: httpx.Request) -> str | None:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Basic "):
            self.violations.append(f"ConnectWise request without Basic auth: {request.url.path}")
            return None
        decoded = base64.b64decode(auth[6:]).decode()
        if not re.fullmatch(r"[^+:]+\+[^:]+:.+", decoded):
            self.violations.append("ConnectWise Basic auth is not companyId+publicKey:privateKey")
            return None
        for name, value in SYNTHETIC_PSA.items():
            if value == decoded:
                return name
        self.violations.append("ConnectWise request with unknown credentials")
        return None

    def _check(self, request: httpx.Request) -> tuple[str, str | None]:
        host = request.url.host
        if host == CW_HOST:
            if not request.headers.get("clientid"):
                self.violations.append("ConnectWise request without clientId header")
            cond = request.url.params.get("conditions")
            if cond is not None and not CONDITIONS_GRAMMAR.match(cond):
                self.violations.append(f"unexpected conditions expression: {cond!r}")
            return "connectwise", self._psa_identity(request)
        if host == ITG_HOST:
            if not request.headers.get("x-api-key"):
                self.violations.append("IT Glue request without x-api-key")
            if request.headers.get("content-type") != "application/vnd.api+json":
                self.violations.append("IT Glue request without Content-Type application/vnd.api+json")
            if "/passwords" in request.url.path or "passwords" in request.url.params.get("include", ""):
                self.violations.append(f"IT Glue password endpoint requested: {request.url}")
            return "itglue", None
        self.violations.append(f"request to unexpected host {host}")
        return "unknown", None

    # --------------------------------------------------------------- matching
    def _matches(self, fx: dict, request: httpx.Request, credential: str | None) -> bool:
        req = fx["request"]
        if req["method"] != request.method or req["host"] != request.url.host or req["path"] != request.url.path:
            return False
        if req.get("credential") and req["credential"] != credential:
            return False
        sent = dict(request.url.params.multi_items())
        return sent == {k: str(v) for k, v in req.get("query", {}).items()}

    def _candidates(self, request: httpx.Request, credential: str | None) -> list[dict]:
        own = [f for f in self.fixtures if self.scenario in f.get("scenarios", []) and self._matches(f, request, credential)]
        if own:
            return own
        return [f for f in self.fixtures if not f.get("scenarios") and self._matches(f, request, credential)]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        system, credential = self._check(request)
        self.requests.append({"system": system, "method": request.method, "path": request.url.path,
                              "query": dict(request.url.params.multi_items()), "credential": credential})
        found = self._candidates(request, credential)
        if not found:
            # Unknown path/params for this credential. Real APIs would answer 400/403/404;
            # we answer 400 and record a violation unless the fixture set expects it.
            self.violations.append(f"no fixture for {request.method} {request.url} as {credential}")
            return httpx.Response(400, json={"code": "NoFixture"}, request=request)
        fx = found[0]
        responses = fx.get("responses") or [fx["response"]]
        resp = responses[min(fx["_served"], len(responses) - 1)]
        fx["_served"] += 1
        if resp.get("delay"):
            import asyncio
            await asyncio.sleep(resp["delay"])
        body = resp.get("body")
        if resp.get("body_repeat"):
            body = {"data": [], "padding": "x" * int(resp["body_repeat"])}
        content = json.dumps(body).encode()
        return httpx.Response(resp["status"], headers=resp.get("headers", {}), content=content, request=request)
