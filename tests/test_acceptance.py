"""Acceptance cases. Every test talks to the connector over real HTTP through the
MCP SDK's Streamable HTTP transport, with ConnectWise and IT Glue replaced by
per-endpoint fixtures (tests/fakes.py). The README table maps each case here."""

from __future__ import annotations

import json
import os
import time

import pytest

from handover.config import Budgets
from support import McpSession

SECRETS = [
    "Tr0ub4dor&3",          # credential line inside a ticket note
    "Winter2026!Srv",       # unexpected 'admin-password' attribute on an IT Glue configuration
    "S3cret-Wifi-Key!",     # Password-kind flexible asset field
    "NFD domain admin",     # Tag field pointing at an IT Glue password
    "not-in-schema-psk",    # trait absent from the field definitions
    "4471",                 # pin inside a Textbox field
    "Ch@ngeMe-2026",        # credential line inside a document section
    "privAliceDEMO0001",    # PSA private key
    "ITG.synthetic-demo-key",
]


def _no_violations(srv):
    assert srv.transport.violations == [], srv.transport.violations


# --------------------------------------------------------------------------- identity
class TestIdentity:
    def test_missing_token_gets_401_with_resource_metadata(self, server):
        r = McpSession(server.url, None).initialize()
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]

    def test_protected_resource_metadata_names_the_issuer(self, server):
        import httpx
        meta = httpx.get(server.url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp")).json()
        assert meta["resource"] == server.resource
        assert meta["authorization_servers"][0].startswith("https://login.example-idp.test/")

    @pytest.mark.parametrize("variant", ["bad_signature", "wrong_audience", "wrong_issuer", "expired"])
    def test_invalid_token_is_refused(self, server, variant):
        from cryptography.hazmat.primitives.asymmetric import rsa
        kw = {}
        if variant == "bad_signature":
            kw["key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = {
            "bad_signature": lambda: server.idp.token("tech-alice", aud=server.resource, **kw),
            "wrong_audience": lambda: server.idp.token("tech-alice", aud="https://other-server.example/mcp"),
            "wrong_issuer": lambda: server.idp.token("tech-alice", aud=server.resource, iss="https://evil.example/"),
            "expired": lambda: server.idp.token("tech-alice", aud=server.resource, ttl=-3600),
        }[variant]()
        assert McpSession(server.url, token).initialize().status_code == 401

    def test_valid_token_for_unknown_principal_is_refused(self, server):
        assert McpSession(server.url, server.token("tech-mallory")).initialize().status_code == 401

    def test_tool_arguments_cannot_change_identity(self, server, session_for):
        s = session_for(server, "tech-bob")
        out = s.call("list_open_tickets", client_ref="CL-0142", cursor=None)
        assert out["status"] == "refused" and out["reason"] == "client_not_allowed"


# ----------------------------------------------------------------------------- scope
class TestScope:
    def test_two_technicians_two_scopes(self, server, session_for):
        alice, bob = session_for(server, "tech-alice"), session_for(server, "tech-bob")
        a = alice.call("list_open_tickets", client_ref="CL-0142")
        assert [t["id"] for t in a["tickets"]] == [48211, 48197, 48150]
        assert bob.call("list_open_tickets", client_ref="CL-0142")["reason"] == "client_not_allowed"
        b = bob.call("list_open_tickets", client_ref="CL-0177")
        assert [t["id"] for t in b["tickets"]] == [48305, 48288]
        assert alice.call("list_open_tickets", client_ref="CL-0177")["reason"] == "client_not_allowed"
        # each technician's calls ran with their own PSA credentials
        used = {(r["credential"], r["query"].get("conditions")) for r in server.transport.requests if r["system"] == "connectwise"}
        assert ("alice", "company/id=250 and closedFlag=false") in used
        assert ("bob", "company/id=263 and closedFlag=false") in used
        _no_violations(server)

    def test_resolve_client_only_lists_authorized_clients(self, server, session_for):
        bob = session_for(server, "tech-bob")
        out = bob.call("resolve_client", query="Northfield")
        assert out["status"] == "no_match" and out["candidates"] == []

    def test_no_psa_credentials_means_refusal_not_shared_key(self, server, session_for):
        carol = session_for(server, "tech-carol")
        out = carol.call("list_open_tickets", client_ref="CL-0177")
        assert out["status"] == "refused" and out["reason"] == "no_psa_credentials"
        assert server.transport.requests == []

    def test_forbidden_ticket_with_authorized_client(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48305)
        assert out["status"] == "refused" and out["reason"] == "ticket_not_in_client"
        assert "Kennel" not in json.dumps(out)

    def test_restricted_document_by_policy(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77002)
        assert out["status"] == "refused" and out["reason"] == "document_not_allowed"
        assert not any("77002" in r["path"] for r in server.transport.requests)  # never even fetched

    def test_restricted_document_in_itglue(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77003)
        assert out["status"] == "refused" and out["reason"] == "document_restricted_in_itglue"
        assert "restricted body" not in json.dumps(out)

    def test_approved_document_excerpt(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77001)
        assert out["status"] == "ok"
        assert "DomainAuthenticated cannot be set by hand" in out["document"]["excerpt"]
        assert "Ch@ngeMe-2026" not in out["document"]["excerpt"]
        assert out["document"]["source"]["system"] == "itglue"


# ------------------------------------------------------------------- client matching
class TestClientMatching:
    def test_same_display_name_is_ambiguous_and_stops(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("resolve_client", query="Summit Accounting")
        assert out["status"] == "ambiguous"
        assert {c["client_ref"] for c in out["candidates"]} == {"CL-0201", "CL-0233"}
        assert server.transport.requests == []  # nothing looked up upstream

    def test_names_differ_between_systems_but_ids_join(self, server, session_for):
        alice = session_for(server, "tech-alice")
        out = alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["client"]["display_name"] == "Northfield Dental Group"   # PSA-side name
        assert [c["name"] for c in out["configurations"]] == ["NFD-FS01", "NFD-FW01"]  # IT Glue org "Northfield Dental"
        itg = [r for r in server.transport.requests if r["path"] == "/configurations"]
        assert all(r["query"]["filter[organization_id]"] == "3101" for r in itg)
        assert all(r["query"]["filter[psa_integration_type]"] == "manage" for r in itg)
        _no_violations(server)


# ------------------------------------------------------------------------- hostile
class TestHostileUpstream:
    def test_out_of_scope_records_from_upstream_are_dropped(self, make_server, session_for):
        srv = make_server(scenario="hostile")
        alice = session_for(srv, "tech-alice")
        lst = alice.call("list_open_tickets", client_ref="CL-0142")
        assert 48404 not in [t["id"] for t in lst["tickets"]]
        assert lst["excluded_out_of_scope_records"] == 1
        ctx = alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert "SUM-S-DC01" not in json.dumps(ctx)
        assert ctx["excluded_out_of_scope_records"] == 1


# ------------------------------------------------------------------------ passwords
class TestPasswordFields:
    def test_password_fields_absent_from_output_and_audit(self, server, session_for):
        alice = session_for(server, "tech-alice")
        outputs = [
            alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211),
            alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77001),
            alice.call("list_open_tickets", client_ref="CL-0142"),
        ]
        blob = json.dumps(outputs) + json.dumps(alice.log)
        audit = (server.app.audit.path).read_text()
        for secret in SECRETS:
            assert secret not in blob, secret
            assert secret not in audit, secret
        ctx = outputs[0]
        summary = ctx["site_summary"]
        assert "Wi-Fi key" not in summary["fields"] and "Domain admin" not in summary["fields"]
        assert summary["fields_omitted"] == {"password_fields": 2, "other_fields": 1}
        assert summary["fields"]["Firewall"] == ["NFD-FW01"]
        assert all("admin-password" not in c and "notes" not in c for c in ctx["configurations"])
        assert any(n.get("content_policy_applied") for n in ctx["history"])

    def test_no_password_endpoint_is_ever_called(self, server, session_for):
        alice = session_for(server, "tech-alice")
        alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77001)
        assert not any("password" in r["path"] for r in server.transport.requests)
        _no_violations(server)

    def test_schema_unavailable_omits_all_traits(self, make_server, session_for):
        srv = make_server(scenario="fields_unavailable")
        out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["site_summary"]["fields"] == {}
        assert out["site_summary"]["fields_omitted"]["reason"] == "field_definitions_unavailable"
        assert "Metro Fiber" not in json.dumps(out)


# ------------------------------------------------------------- reuse and revocation
class TestReuseAndRevocation:
    def test_session_of_another_user_is_refused(self, server, session_for):
        alice = session_for(server, "tech-alice")
        bob = McpSession(server.url, server.token("tech-bob"))
        bob.session_id = alice.session_id
        r = bob.rpc("tools/call", {"name": "list_open_tickets", "arguments": {"client_ref": "CL-0201"}})
        assert r.status_code in (403, 404)
        assert "tickets" not in r.text

    def test_cursor_of_another_user_or_client_is_refused(self, server, session_for):
        alice, bob = session_for(server, "tech-alice"), session_for(server, "tech-bob")
        first = bob.call("list_open_tickets", client_ref="CL-0201")
        assert first["has_more"] is True and len(first["tickets"]) == 25
        cursor = first["cursor"]
        assert alice.call("list_open_tickets", client_ref="CL-0201", cursor=cursor)["reason"] == "invalid_cursor"
        assert alice.call("list_open_tickets", client_ref="CL-0233", cursor=cursor)["reason"] == "invalid_cursor"
        tampered = cursor[:-2] + ("AA" if not cursor.endswith("AA") else "BB")
        assert bob.call("list_open_tickets", client_ref="CL-0201", cursor=tampered)["reason"] == "invalid_cursor"

    def test_no_response_cache_shared_between_users(self, server, session_for):
        alice, bob = session_for(server, "tech-alice"), session_for(server, "tech-bob")
        alice.call("list_open_tickets", client_ref="CL-0201")
        n = len(server.transport.requests)
        bob.call("list_open_tickets", client_ref="CL-0201")
        # Bob's call went upstream again with Bob's own credentials, nothing was served from Alice's call.
        assert len(server.transport.requests) > n
        assert server.transport.requests[n]["credential"] == "bob"

    def test_revocation_after_a_successful_request(self, server, session_for):
        alice = session_for(server, "tech-alice")
        assert alice.call("list_open_tickets", client_ref="CL-0142")["status"] == "ok"
        policy = json.loads(server.policy_path.read_text())
        policy["disabled_principals"].append("https://login.example-idp.test/msp-tenant/v2.0|tech-alice")
        policy["version"] = "2026-10-09.2"
        server.policy_path.write_text(json.dumps(policy))
        os.utime(server.policy_path, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
        r = alice.rpc("tools/call", {"name": "list_open_tickets", "arguments": {"client_ref": "CL-0142"}})
        assert r.status_code == 401


# ------------------------------------------------------- limits, failures, partials
class TestLimitsAndFailures:
    def test_pagination_with_bound_cursor_reaches_the_end(self, server, session_for):
        bob = session_for(server, "tech-bob")
        first = bob.call("list_open_tickets", client_ref="CL-0201")
        second = bob.call("list_open_tickets", client_ref="CL-0201", cursor=first["cursor"])
        ids = [t["id"] for t in first["tickets"] + second["tickets"]]
        assert len(ids) == 32 and len(set(ids)) == 32
        assert second["has_more"] is False and "cursor" not in second
        _no_violations(server)

    def test_output_budget_truncates_with_cursor_not_silently(self, make_server, session_for):
        srv = make_server(budgets=Budgets(max_output_chars=2500))
        bob = session_for(srv, "tech-bob")
        seen, cursor, calls = [], None, 0
        while True:
            out = bob.call("list_open_tickets", client_ref="CL-0201", cursor=cursor)
            calls += 1
            assert len(json.dumps(out["tickets"])) <= 2500
            seen += [t["id"] for t in out["tickets"]]
            if not out["has_more"]:
                break
            cursor = out["cursor"]
            assert calls < 40
        assert len(seen) == 32 and len(set(seen)) == 32 and calls > 2

    def test_itglue_429_is_reported_not_turned_into_no_documentation(self, make_server, session_for):
        srv = make_server(scenario="itglue_429")
        out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["status"] == "partial"
        itg = next(s for s in out["sources"] if s["system"] == "itglue")
        assert itg["status"] == "unavailable" and itg["reason"] == "rate_limited"
        assert "missing, not absent" in out["message"]
        assert out["ticket"]["id"] == 48211 and out["history"]  # PSA facts still delivered
        assert srv.sleeps == []  # a 120 s Retry-After is not slept on inside a tool call
        audit = srv.app.audit.records[-1]
        assert audit["sources_unavailable"] == ["itglue"] and audit["decision"] == "partial"

    def test_short_429_is_retried_after_the_requested_wait(self, make_server, session_for):
        srv = make_server(scenario="itglue_429_short")
        out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["status"] == "ok"
        assert srv.sleeps == [2.0]

    def test_timeout_is_reported(self, make_server, session_for):
        srv = make_server(scenario="itglue_timeout", budgets=Budgets(upstream_timeout_s=0.3, max_retries=0))
        out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        itg = next(s for s in out["sources"] if s["system"] == "itglue")
        assert out["status"] == "partial" and itg["reason"] == "timeout"

    def test_oversized_upstream_response_is_an_error_not_an_empty_answer(self, make_server, session_for):
        srv = make_server(scenario="huge_body")
        out = session_for(srv, "tech-alice").call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        assert out["status"] == "unavailable"
        assert out["sources"][0]["reason"] == "response_too_large"

    def test_shared_upstream_budget_is_enforced(self, make_server, session_for):
        srv = make_server(budgets=Budgets(connectwise_requests_per_window=2))
        alice, bob = session_for(srv, "tech-alice"), session_for(srv, "tech-bob")
        assert alice.call("list_open_tickets", client_ref="CL-0142")["status"] == "ok"
        assert bob.call("list_open_tickets", client_ref="CL-0177")["status"] == "ok"
        out = alice.call("list_open_tickets", client_ref="CL-0142")
        assert out["status"] == "partial"
        assert out["sources"][0]["reason"] == "request_budget_exhausted"


# ---------------------------------------------------------------------------- audit
class TestAudit:
    def test_every_call_is_audited_without_content(self, server, session_for):
        alice = session_for(server, "tech-alice")
        alice.call("resolve_client", query="Northfield")
        alice.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
        alice.call("get_document_excerpt", client_ref="CL-0142", document_id=77002)
        lines = [json.loads(l) for l in server.app.audit.path.read_text().splitlines()]
        assert [l["tool"] for l in lines] == ["resolve_client", "get_ticket_context", "get_document_excerpt"]
        assert [l["decision"] for l in lines] == ["ok", "allowed", "refused"]
        for l in lines:
            assert set(l) == {"ts", "correlation_id", "principal", "client_ref", "tool", "decision", "reason",
                              "policy_version", "source_ids", "sources_unavailable"}
            assert l["principal"] == "https://login.example-idp.test/msp-tenant/v2.0|tech-alice"
            assert l["policy_version"] == "2026-10-09.1"
        ctx = lines[1]
        assert "cw:ticket/48211" in ctx["source_ids"] and "itg:configuration/553201" in ctx["source_ids"]
        raw = server.app.audit.path.read_text()
        for text in ["imaging share", "Network profile", "Metro Fiber", "Bearer", "eyJ"]:
            assert text not in raw

    def test_tools_are_declared_read_only(self, server, session_for):
        s = session_for(server, "tech-alice")
        tools = s.rpc("tools/list").json()["result"]["tools"]
        assert {t["name"] for t in tools} == {"resolve_client", "list_open_tickets", "get_ticket_context", "get_document_excerpt"}
        for t in tools:
            assert t["annotations"]["readOnlyHint"] is True
            assert t["annotations"]["destructiveHint"] is False
            assert t.get("title")
