"""The attack scripts of the independent review (a1 to a6), kept as regression tests.
a1 lives in test_content_policy.py; a2 to a6 are here."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import shutil
import time
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from handover.audit import AuditLog
from handover.config import Budgets
from handover.credentials import CredentialStore
from handover.cursor import CursorCodec
from handover.identity import JwtVerifier, Principal
from handover.itglue import ITGlue
from handover.policy import Policy
from handover.tools import Handover, enforce_budget
from handover.upstream import Deadline, SharedBudget, SourceUnavailable, send
from support import ISSUER, ROOT, McpSession, TestIdP, start

ALICE = Principal(ISSUER, "tech-alice")


# ------------------------------------------------------------------ a2: IT Glue site summary
FIELDS = {"data": [
    {"attributes": {"name-key": "admin-password", "name": "Admin password", "kind": "Text"}},
    {"attributes": {"name-key": "notes", "name": "Notes", "kind": "Textbox"}},
    {"attributes": {"name-key": "big", "name": "Big", "kind": "Text"}},
    {"attributes": {"name-key": "creds", "name": "Creds", "kind": "Tag", "tag-type": "FlexibleAssetType: 12"}},
    {"attributes": {"name-key": "pw2", "name": "Router", "kind": "Tag", "tag-type": "passwords"}},
    {"attributes": {"name-key": "isp", "name": "Internet provider", "kind": "Text"}},
]}
FA = {"data": [{"id": "9", "attributes": {"organization-id": 3101, "name": "Site", "traits": {
    "admin-password": "Hunter2-TEXT", "notes": "Wifi password is Hunter2-BOX", "big": "x" * 200_000,
    "creds": {"type": "FlexibleAssetType", "values": [{"id": 1, "name": "Domain admin creds"}]},
    "pw2": {"type": "Passwords", "values": [{"id": 2, "name": "Router admin"}]},
    "isp": "Metro Fiber"}}}]}


def _itglue(handler, type_id=41):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ITGlue("https://api.itglue.com", "k", http, SharedBudget(100, 300), Budgets(), site_summary_type_id=type_id)


def test_a2_site_summary_secret_named_text_field_and_big_text():
    def handler(req):
        return httpx.Response(200, json=FIELDS if "flexible_asset_fields" in req.url.path else FA)
    out = asyncio.run(_itglue(handler).site_summary(3101, Deadline.after(20)))
    s = json.dumps(out)
    assert "Hunter2-TEXT" not in s and "Hunter2-BOX" not in s
    assert "Domain admin creds" not in s and "Router admin" not in s
    assert out["fields"]["Internet provider"] == "Metro Fiber"
    assert out["fields_omitted"] == {"password_fields": 1, "secret_named_fields": 2}
    assert out["truncated_fields"] == ["Big"] and len(out["fields"]["Big"]) <= Budgets().max_note_chars
    assert out["content_policy_applied"] == ["Notes"]
    assert len(s) < 2_000


def test_site_summary_type_is_configuration_not_a_constant():
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, json=FIELDS if "flexible_asset_fields" in req.url.path else FA)
    asyncio.run(_itglue(handler, type_id=77).site_summary(3101, Deadline.after(20)))
    assert any("flexible-asset-type-id%5D=77" in u for u in seen) and not any("=41" in u for u in seen)
    assert asyncio.run(_itglue(handler, type_id=None).site_summary(3101, Deadline.after(20))) is None


# --------------------------------------------------- a3: end to end, malformed upstreams, failures
def _fixtures_copy(tmp: Path) -> Path:
    dst = tmp / "fixtures"
    shutil.copytree(ROOT / "fixtures", dst)
    return dst


def _edit(root: Path, rel: str, fn) -> None:
    p = root / rel
    d = json.loads(p.read_text())
    fn(d)
    p.write_text(json.dumps(d))


@pytest.fixture
def run(tmp_path):
    servers = []

    def _run(edit=None, **kw):
        fx = _fixtures_copy(tmp_path)
        if edit:
            _edit(fx, *edit)
        work = tmp_path / f"server{len(servers)}"
        work.mkdir()
        srv = start(work, fixtures=fx, **kw)
        servers.append(srv)
        s = McpSession(srv.url, srv.token("tech-alice"))
        assert s.initialize().status_code == 200
        return srv, s
    yield _run
    for s in servers:
        s.stop()


def _audit_lines(srv):
    return [json.loads(l) for l in srv.app.audit.path.read_text().splitlines()] if srv.app.audit.path.exists() else []


def test_a3_200k_text_field_stays_under_the_output_budget(run):
    srv, s = run(("itglue/flexible-assets-site-summary-3101.json",
                  lambda d: d["response"]["body"]["data"][0]["attributes"]["traits"].__setitem__("backup-window", "B" * 200_000)))
    r = s.rpc("tools/call", {"name": "get_ticket_context", "arguments": {"client_ref": "CL-0142", "ticket_id": 48211}})
    payload = json.loads(r.json()["result"]["content"][0]["text"])
    assert len(json.dumps(payload, ensure_ascii=False)) <= Budgets().max_output_chars
    assert payload["site_summary"]["truncated_fields"] == ["Backup window"]


def test_every_tool_result_is_capped_and_flagged():
    big = {"status": "ok", "a": "x" * 200_000, "items": [{"t": "y" * 300} for _ in range(500)], "correlation_id": "c"}
    out = enforce_budget(big, 24_000)
    assert len(json.dumps(out)) <= 24_000 and out["truncated"] is True and out["correlation_id"] == "c"


def test_a3_tiny_budget_still_caps_ticket_context(make_server, session_for):
    srv = make_server(budgets=Budgets(max_output_chars=3_000))
    out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert len(json.dumps(out, ensure_ascii=False)) <= 3_000
    assert out.get("truncated") or out.get("history_truncated")


def test_a3_malformed_company_id_is_an_audited_error_not_a_crash(run):
    srv, s = run(("connectwise/ticket-48211.json", lambda d: d["response"]["body"]["company"].__setitem__("id", "SECRET-from-upstream")))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert out["status"] == "unavailable" and out["sources"][0]["reason"] == "bad_response"
    assert "SECRET-from-upstream" not in json.dumps(out)
    lines = _audit_lines(srv)
    assert lines[-1]["decision"] == "failed" and "SECRET" not in srv.app.audit.path.read_text()


def test_a3_organization_without_id_is_reported_partial_and_audited(run):
    srv, s = run(("itglue/organization-3101.json", lambda d: d["response"]["body"].__setitem__("data", {"type": "organizations"})))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert out["status"] == "partial"
    assert next(x for x in out["sources"] if x["system"] == "itglue")["reason"] == "bad_response"
    assert _audit_lines(srv)[-1]["decision"] == "partial"


@pytest.mark.parametrize("cursor", ["abc.é", "nodot", "a.b.c", "!!!.x", "éé.é"])
def test_a3_garbage_cursor_is_refused_and_audited(server, session_for, cursor):
    out = session_for(server, "tech-alice").call("list_open_tickets", client_ref="CL-0142", cursor=cursor)
    assert out["status"] == "refused" and out["reason"] == "invalid_cursor"
    assert _audit_lines(server)[-1]["reason"] == "invalid_cursor"


def test_a3_unexpected_internal_error_is_audited(server, session_for, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("upstream said Hunter2")
    monkeypatch.setattr(server.app.handover.connectwise, "notes", boom)
    out = session_for(server, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert out["status"] == "error" and out["reason"] == "internal_error" and "Hunter2" not in json.dumps(out)
    last = _audit_lines(server)[-1]
    assert last["decision"] == "error" and last["reason"] == "internal_error:RuntimeError"
    assert "Hunter2" not in server.app.audit.path.read_text()


def test_a3_unwritable_audit_log_returns_no_data(server, session_for):
    s = session_for(server, "tech-alice")
    server.app.audit.path.write_text("")
    os.chmod(server.app.audit.path, 0o400)
    try:
        if os.access(server.app.audit.path, os.W_OK):
            pytest.skip("running as a user who can write read-only files")
        out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["status"] == "error" and out["reason"] == "audit_unavailable"
        assert "ticket" not in out and "history" not in out
    finally:
        os.chmod(server.app.audit.path, 0o600)


@pytest.mark.parametrize("ticket_id", [-1, 0, 10**20])
def test_a3_odd_ticket_ids_do_not_crash(server, session_for, ticket_id):
    out = session_for(server, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=ticket_id)
    assert out["status"] == "rejected" and out["reason"] == "invalid_arguments"
    assert _audit_lines(server)[-1]["tool"] == "get_ticket_context"


# ------------------------------------------------------------------------ a4: pagination
class FakeCW:
    def __init__(self, rows, page_size):
        self.rows, self.ps, self.calls = rows, page_size, 0

    async def open_tickets(self, cred, company_id, page, deadline):
        self.calls += 1
        chunk = [dict(r) for r in self.rows[(page - 1) * self.ps: page * self.ps]]
        return chunk, len(chunk) >= self.ps


def _rows(n, hostile_every=0, big=0):
    return [{"id": 1000 - i, "company_id": 999 if hostile_every and i % hostile_every == 0 else 250, "summary": "s" * big}
            for i in range(n)]


def _walk(tmp_path, rows, budgets, max_calls=60):
    h = Handover(Policy(ROOT / "config/policy.example.json"), CredentialStore(ROOT / "config/psa-credentials.example.json"),
                 FakeCW(rows, budgets.max_records), None, CursorCodec(b"x" * 32), AuditLog(tmp_path / "a.jsonl"), budgets)
    seen, cur, calls, outs = [], None, 0, []
    while calls < max_calls:
        out = asyncio.run(h.list_open_tickets(ALICE, "CL-0142", cur))
        calls += 1
        outs.append(out)
        seen += [t["id"] for t in out["tickets"]]
        if not out["has_more"]:
            break
        cur = out["cursor"]
    return calls, seen, outs


@pytest.mark.parametrize("n,hostile,big,budget,max_calls", [
    (0, 0, 0, Budgets(), 1), (25, 0, 0, Budgets(), 1), (26, 0, 0, Budgets(), 2), (100, 0, 0, Budgets(), 4),
    (101, 0, 0, Budgets(), 5), (130, 3, 0, Budgets(), 4), (40, 0, 300, Budgets(max_output_chars=2_500), 40),
])
def test_a4_pagination_reaches_the_end_exactly(tmp_path, n, hostile, big, budget, max_calls):
    rows = _rows(n, hostile, big)
    calls, seen, _ = _walk(tmp_path, rows, budget)
    assert seen == [r["id"] for r in rows if r["company_id"] == 250]
    assert calls <= max_calls


def test_a4_exactly_one_full_page_does_not_announce_more(tmp_path):
    calls, seen, outs = _walk(tmp_path, _rows(25), Budgets())
    assert calls == 1 and len(seen) == 25 and outs[0]["has_more"] is False


def test_a4_record_bigger_than_the_budget_cannot_loop(tmp_path):
    calls, seen, outs = _walk(tmp_path, _rows(3, big=3_000), Budgets(max_output_chars=2_000))
    assert calls < 5 and seen == []
    assert sum(o.get("skipped_oversized_records", 0) for o in outs) == 3
    assert all(o.get("truncated") for o in outs if o.get("skipped_oversized_records"))


# ------------------------------------------------------------------------- a5: retries
def _send(statuses, headers=None, max_retries=2):
    seq, sleeps, n = list(statuses), [], [0]

    def h(req):
        n[0] += 1
        return httpx.Response(seq.pop(0) if seq else 200, headers=headers or {}, json={"secret_body": "Hunter2"})

    async def sl(x):
        sleeps.append(x)

    async def go():
        c = httpx.AsyncClient(transport=httpx.MockTransport(h))
        try:
            r = await send(c, c.build_request("GET", "https://x/y"), system="itglue", budget=SharedBudget(100, 300),
                           deadline=Deadline.after(20), timeout_s=8, max_retries=max_retries, max_retry_wait_s=10,
                           max_bytes=10**6, sleep=sl)
            return "ok", r.status_code, n[0], sleeps
        except SourceUnavailable as e:
            return "unavailable", e.public(), n[0], sleeps
    return asyncio.run(go())


def test_a5_429_without_retry_after_says_so():
    kind, info, n, sleeps = _send([429, 429, 429])
    assert kind == "unavailable" and info["reason"] == "rate_limited" and n == 3 and sleeps == [1.0, 2.0]
    assert info["detail"] == ("The source answered 429 Too Many Requests 3 time(s) without a usable "
                              "Retry-After; gave up after a bounded backoff.")  # quoted in the README
    assert "Hunter2" not in json.dumps(info)


def test_a5_retry_after_as_http_date_is_honoured():
    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=4), usegmt=True)
    kind, status, n, sleeps = _send([429], {"Retry-After": when})
    assert kind == "ok" and n == 2 and len(sleeps) == 1 and 2.0 <= sleeps[0] <= 4.5


def test_a5_far_http_date_is_not_slept_on():
    when = format_datetime(datetime.now(timezone.utc) + timedelta(hours=2), usegmt=True)
    kind, info, n, sleeps = _send([429], {"Retry-After": when})
    assert kind == "unavailable" and sleeps == [] and "Retry-After" in info["detail"]


@pytest.mark.parametrize("value", ["nan", "inf", "soon"])
def test_a5_unreadable_retry_after_is_treated_as_absent(value):
    kind, info, n, sleeps = _send([429, 429, 429], {"Retry-After": value})
    assert kind == "unavailable" and "without a usable Retry-After" in info["detail"]


def test_a5_huge_retry_after_is_not_retried():
    kind, info, n, sleeps = _send([429], {"Retry-After": "1e9"})
    assert kind == "unavailable" and n == 1 and sleeps == []


@pytest.mark.parametrize("statuses,expected", [([503, 503], "ok"), ([503, 503, 503], "upstream_http_503"),
                                               ([500, 401], "upstream_http_401")])
def test_a5_server_errors(statuses, expected):
    kind, info, n, sleeps = _send(statuses)
    assert (kind == "ok") if expected == "ok" else (info["reason"] == expected)


# ----------------------------------------------------------------------------- a6: JWT
def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def test_a6_token_forgeries_are_refused():
    idp, aud = TestIdP(), "https://h.example/mcp"
    v = JwtVerifier(issuer=ISSUER, audience=aud, resource_url=aud, jwks=idp.jwks, is_authorized=lambda p: True)
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "tech-alice", "aud": aud, "exp": now + 600}
    pem = idp.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    h, p = _b64({"alg": "HS256", "kid": "test-key-1", "typ": "JWT"}), _b64(claims)
    hs = f"{h}.{p}." + base64.urlsafe_b64encode(hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
    kid = {"kid": "test-key-1"}
    cases = {
        "valid": (idp.token("tech-alice", aud=aud), True),
        "aud list including ours": (idp.token("tech-alice", aud=[aud, "other"]), True),
        "alg none": (_b64({"alg": "none", "kid": "test-key-1"}) + "." + p + ".", False),
        "HS256 signed with the public key": (hs, False),
        "no kid": (jwt.encode(claims, idp.key, algorithm="RS256"), False),
        "no exp": (jwt.encode({k: v for k, v in claims.items() if k != "exp"}, idp.key, algorithm="RS256", headers=kid), False),
        "nbf in the future": (jwt.encode({**claims, "nbf": now + 3600}, idp.key, algorithm="RS256", headers=kid), False),
    }
    for name, (token, accepted) in cases.items():
        assert (asyncio.run(v.verify_token(token)) is not None) is accepted, name
