"""Cases added after the second independent review (V1 to V13). Every test crosses the
MCP HTTP endpoint, with a private copy of the fixtures edited for the case."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

from handover.config import Budgets
from handover.content import clean
from support import ROOT, McpSession, start


def _edit(root: Path, rel: str, fn) -> None:
    p = root / rel
    d = json.loads(p.read_text())
    fn(d)
    p.write_text(json.dumps(d))


@pytest.fixture
def srv_with(tmp_path):
    started = []

    def _start(*edits, add: dict | None = None, who: str = "tech-alice", **kw):
        n = len(started)
        fx = tmp_path / f"fixtures{n}"
        shutil.copytree(ROOT / "fixtures", fx)
        for rel, fn in edits:
            _edit(fx, rel, fn)
        for rel, content in (add or {}).items():
            (fx / rel).write_text(json.dumps(content))
        work = tmp_path / f"server{n}"
        work.mkdir()
        srv = start(work, fixtures=fx, **kw)
        started.append(srv)
        s = McpSession(srv.url, srv.token(who))
        assert s.initialize().status_code == 200
        return srv, s
    yield _start
    for s in started:
        s.stop()


def _seen(srv, s) -> str:
    """Everything that left the server: MCP responses and the audit log."""
    audit = srv.app.audit.path.read_text() if srv.app.audit.path.exists() else ""
    return json.dumps([e["response"] for e in s.log]) + audit


def _audit(srv) -> list[dict]:
    return [json.loads(l) for l in srv.app.audit.path.read_text().splitlines()]


def _ticket_body(d):
    return d["response"]["body"]


def _doc_attrs(d):
    return d["response"]["body"]["data"]["attributes"]


NOTE = "connectwise/ticket-48211-notes.json"
CFG = "itglue/configurations-3101-psa-9120.json"
SUMMARY = "itglue/flexible-assets-site-summary-3101.json"


# --------------------------------------------------------------------------- V1
def test_v1_objects_in_scalar_fields_are_omitted_and_reported(srv_with):
    srv, s = srv_with(
        ("connectwise/ticket-48211.json", lambda d: _ticket_body(d)["company"].__setitem__("identifier", {"x": "MARKER-V1A"})),
        ("itglue/document-77001.json", lambda d: _doc_attrs(d).update({"name": {"n": "MARKER-V1B"}, "updated-at": {"d": "MARKER-V1C"}})),
    )
    ctx = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    doc = s.call("get_document_excerpt", client_ref="CL-0142", document_id=77001)
    assert "company_identifier" in ctx["ticket"]["omitted_malformed_fields"]
    assert set(doc["document"]["omitted_malformed_fields"]) == {"name", "updated_at"}
    for marker in ("MARKER-V1A", "MARKER-V1B", "MARKER-V1C"):
        assert marker not in _seen(srv, s)


# --------------------------------------------------------------------------- V2
def test_v2_secret_in_a_configuration_name_and_a_tag_name_is_withheld(srv_with):
    srv, s = srv_with(
        (CFG, lambda d: d["response"]["body"]["data"][0]["attributes"].__setitem__("name", "Password: MARKER-V2A")),
        (SUMMARY, lambda d: d["response"]["body"]["data"][0]["attributes"]["traits"]["firewall"]["values"].append(
            {"id": 9, "name": "Password: MARKER-V2B"})),
    )
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert "MARKER-V2A" not in _seen(srv, s) and "MARKER-V2B" not in _seen(srv, s)
    assert "name" in out["configurations"][0]["content_policy_applied"]
    assert out["site_summary"]["fields"]["Firewall"] == ["NFD-FW01"]


# --------------------------------------------------------------------------- V3
@pytest.mark.parametrize("text", [
    "**Password:**\nMARKER-V3",
    "__Wi-Fi key__ -\n\nMARKER-V3",
    "Password:\n```\nMARKER-V3\nsecond line MARKER-V3\n```",
    "### Credentials\n~~~text\nMARKER-V3\n~~~",
    "> **PIN**\n> MARKER-V3",
])
def test_v3_markdown_labels_and_code_blocks(srv_with, text):
    full = "Before the label.\n" + text + "\nAfter the label."
    srv, s = srv_with((NOTE, lambda d: d["response"]["body"][-1].__setitem__("text", full)))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert "MARKER-V3" not in _seen(srv, s)
    first = next(n for n in out["history"] if n["id"] == 910331)
    assert first["text"].startswith("Before the label.") and first["text"].endswith("After the label.")


# --------------------------------------------------------------------------- V4
def test_v4_document_returned_with_another_id_is_refused(srv_with):
    srv, s = srv_with(("itglue/document-77001.json", lambda d: d["response"]["body"]["data"].__setitem__("id", "77002")))
    out = s.call("get_document_excerpt", client_ref="CL-0142", document_id=77001)
    assert out["status"] == "refused" and out["reason"] == "upstream_record_mismatch" and "document" not in out
    last = _audit(srv)[-1]
    assert last["decision"] == "refused"
    assert last["source_ids"] == ["received:itg:document/77002", "requested:itg:document/77001"]


def test_v4_record_of_another_type_is_refused(srv_with):
    srv, s = srv_with(("itglue/document-77001.json", lambda d: d["response"]["body"]["data"].__setitem__("type", "flexible-assets")))
    out = s.call("get_document_excerpt", client_ref="CL-0142", document_id=77001)
    assert out["reason"] == "upstream_record_mismatch" and "excerpt" not in json.dumps(out)


def test_v4_ticket_returned_with_another_id_is_refused(srv_with):
    srv, s = srv_with(("connectwise/ticket-48211.json", lambda d: _ticket_body(d).__setitem__("id", 48197)))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert out["status"] == "refused" and out["reason"] == "upstream_record_mismatch" and "ticket" not in out
    assert _audit(srv)[-1]["source_ids"] == ["received:cw:ticket/48197", "requested:cw:ticket/48211"]


# --------------------------------------------------------------------------- V5
def test_v5_free_client_ref_never_reaches_the_audit_or_the_message(srv_with):
    srv, s = srv_with()
    for tool, args in [("list_open_tickets", {}), ("get_ticket_context", {"ticket_id": 48211}),
                       ("get_document_excerpt", {"document_id": 77001})]:
        out = s.call(tool, client_ref="password=MARKER-V5", **args)
        assert out["status"] == "refused" and out["reason"] == "client_not_allowed"
    assert "MARKER-V5" not in _seen(srv, s)
    assert all(l["client_ref"] is None for l in _audit(srv))


def test_v5_overlong_arguments_are_rejected_without_echo(srv_with):
    srv, s = srv_with()
    r = s.rpc("tools/call", {"name": "resolve_client", "arguments": {"query": "MARKER-V5L" * 50}})
    assert r.json()["result"]["isError"] is True
    assert "MARKER-V5L" not in _seen(srv, s)


# --------------------------------------------------------------------------- V6
def test_v6_schema_rejection_is_audited_once_without_the_value(srv_with):
    srv, s = srv_with()
    r = s.rpc("tools/call", {"name": "get_ticket_context", "arguments": {"client_ref": "CL-0142", "ticket_id": "invalid-MARKER-V6"}})
    result = r.json()["result"]
    assert result["isError"] is True and json.loads(result["content"][0]["text"])["reason"] == "invalid_arguments"
    lines = _audit(srv)
    assert len(lines) == 1
    assert lines[0]["decision"] == "rejected_invalid_arguments" and lines[0]["tool"] == "get_ticket_context"
    assert lines[0]["principal"].endswith("|tech-alice")
    assert "MARKER-V6" not in _seen(srv, s)


def test_v6_unknown_tool_is_audited(srv_with):
    srv, s = srv_with()
    r = s.rpc("tools/call", {"name": "get_password-MARKER", "arguments": {}})
    assert r.json()["result"]["isError"] is True
    assert _audit(srv)[-1]["tool"] == "unknown_tool" and "MARKER" not in _seen(srv, s)


# --------------------------------------------------------------------------- V7
def test_v7_pathological_text_is_processed_quickly():
    t0 = time.perf_counter()
    clean("admin" + "a" * 64_000, 600)
    clean("Local admin " + " " * 64_000 + "x", 600)
    clean("password" + " " * 64_000 + "x", 600)
    assert time.perf_counter() - t0 < 1.0


def test_v7_large_note_crosses_the_mcp_boundary_in_time(srv_with):
    big = "admin" + "a" * 64_000
    assert len(big) == 64_005
    srv, s = srv_with((NOTE, lambda d: d["response"]["body"][-1].__setitem__("text", big)))
    t0 = time.perf_counter()
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert time.perf_counter() - t0 < 5.0 and out["status"] == "ok"
    first = next(n for n in out["history"] if n["id"] == 910331)
    assert "text" in first["truncated_fields"]


# --------------------------------------------------------------------------- V8
def test_v8_budget_is_measured_on_the_text_mcp_sends(srv_with):
    srv, s = srv_with()
    natural = len(s.rpc("tools/call", {"name": "get_ticket_context",
                                       "arguments": {"client_ref": "CL-0142", "ticket_id": 48211}}).json()["result"]["content"][0]["text"])
    srv.stop()
    limit = natural - 200
    srv2, s2 = srv_with(budgets=Budgets(max_output_chars=limit))
    text = s2.rpc("tools/call", {"name": "get_ticket_context",
                                 "arguments": {"client_ref": "CL-0142", "ticket_id": 48211}}).json()["result"]["content"][0]["text"]
    assert len(text) <= limit
    out = json.loads(text)
    assert out.get("truncated") is True or "history_truncated" in out


# --------------------------------------------------------------------------- V9
def test_v9_many_configurations_per_filter_are_bounded_and_flagged(srv_with):
    def many(d):
        base = d["response"]["body"]["data"][0]
        d["response"]["body"]["data"] = [
            {**base, "id": str(600000 + i), "attributes": {**base["attributes"], "name": f"NFD-WS{i:02d}"}} for i in range(30)]
    srv, s = srv_with((CFG, many))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert len(out["configurations"]) == 25 and out["configurations_has_more"] is True


# -------------------------------------------------------------------------- V10
def test_v10_ticket_context_lists_approved_documents_and_the_chain_closes(srv_with):
    srv, s = srv_with()
    ctx = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    docs = ctx["approved_documents"]
    assert [d["id"] for d in docs] == [77001, 77003]
    assert docs[0]["title"] == "Imaging share (S:) troubleshooting" and docs[0]["source"]["system"] == "policy"
    out = s.call("get_document_excerpt", client_ref="CL-0142", document_id=docs[0]["id"])
    assert out["status"] == "ok"
    trace = (ROOT / "docs" / "demo-trace.md").read_text()
    assert "`document_id` taken from get_ticket_context.approved_documents[0].id" in trace


# -------------------------------------------------------------------------- V13
def test_v13_two_site_summaries_are_reported_as_ambiguous(srv_with):
    def two(d):
        first = d["response"]["body"]["data"][0]
        d["response"]["body"]["data"].append({**first, "id": "640119"})
    srv, s = srv_with((SUMMARY, two))
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    assert out["site_summary"]["status"] == "ambiguous"
    assert out["site_summary"]["candidate_ids"] == [640118, 640119] and "fields" not in out["site_summary"]


def test_v13_field_definitions_follow_pages(srv_with):
    fields = "itglue/flexible-asset-fields-41.json"
    holder = {}

    def split(d):
        data = d["response"]["body"]["data"]
        holder["second"] = data[4:]
        d["response"]["body"]["data"] = data[:4]
        d["response"]["body"]["meta"] = {"current-page": 1, "next-page": 2, "total-pages": 2}
    fx_root = ROOT / "fixtures"
    page1 = json.loads((fx_root / fields).read_text())
    split(page1)
    page2 = {"id": "itg.flexible-asset-fields.41.p2",
             "request": {**page1["request"], "query": {"page[size]": 100, "page[number]": 2}},
             "provenance": {"status": "verified", "note": "page 2 of the field definitions"},
             "response": {"status": 200, "headers": {}, "body": {"data": holder["second"], "meta": {"current-page": 2, "next-page": None}}}}
    srv, s = srv_with((fields, split), add={"itglue/flexible-asset-fields-41-p2.json": page2})
    out = s.call("get_ticket_context", client_ref="CL-0142", ticket_id=48211)
    summary = out["site_summary"]
    assert "Backup window" in summary["fields"]  # defined on page 2
    assert summary["fields_omitted"]["password_fields"] == 2
    assert srv.transport.violations == []
