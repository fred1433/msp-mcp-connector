"""The four read-only tools, independent of the MCP transport.

resolve_client       -> which client do you mean (by internal reference, never joined by name)
list_open_tickets    -> open PSA tickets for one client, paginated with a bound cursor
get_ticket_context   -> one ticket, its history, the IT Glue configurations it concerns,
                        and the client's site summary, each fact with its source
get_document_excerpt -> an approved excerpt of one IT Glue document

Every call: principal from the validated token, grant from the policy, client
link from the policy, upstream calls with that principal's PSA credentials,
output built from allowlists, the output budget applied to the whole result,
and one audit record, including when the call fails.
"""

from __future__ import annotations

import functools
import sys

import pydantic_core
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .audit import AuditLog, AuditUnavailable
from .config import Budgets
from .connectwise import ConnectWise
from .credentials import CredentialStore
from .cursor import CursorCodec
from .identity import Principal
from .itglue import DocumentRestricted, ITGlue, RecordMismatch
from .policy import ClientLink, Grant, Policy, PolicyError
from .upstream import Deadline, SourceUnavailable

TRUNCATION_MESSAGE = "Part of this result was cut to stay within the output budget; ask for a narrower item to see more."


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def mcp_text(obj: Any) -> str:
    """The exact text the MCP SDK puts in the tool result (mcp.server.mcpserver func_metadata._convert_to_content)."""
    return pydantic_core.to_json(obj, fallback=str, indent=2).decode()


def _size(obj: Any) -> int:
    return len(mcp_text(obj))


MAX_QUERY_CHARS = 100
MAX_CURSOR_CHARS = 2_048


def _longest_string(obj: Any, path: tuple = ()) -> tuple[int, tuple] | None:
    best = None
    if isinstance(obj, str):
        return (len(obj), path)
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else []
    for k, v in items:
        if k in ("source", "correlation_id", "cursor", "status", "reason"):
            continue
        cand = _longest_string(v, path + (k,))
        if cand and (best is None or cand[0] > best[0]):
            best = cand
    return best


def _longest_list(obj: Any, path: tuple = ()) -> tuple[int, tuple] | None:
    best = None
    if isinstance(obj, list):
        best = (len(obj), path)
    items = obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else []
    for k, v in items:
        if k == "sources":
            continue
        cand = _longest_list(v, path + (k,))
        if cand and cand[0] > 0 and (best is None or cand[0] > best[0]):
            best = cand
    return best


def _get(obj: Any, path: tuple) -> Any:
    for k in path:
        obj = obj[k]
    return obj


def enforce_budget(out: dict, limit: int) -> dict:
    """Bring any tool result under `limit` characters, and say so when something was cut.
    First halves the longest strings, then drops trailing list items, then gives up on content."""
    if _size(out) <= limit:
        return out
    out["truncated"] = True
    out["truncation_message"] = TRUNCATION_MESSAGE
    for _ in range(200):
        if _size(out) <= limit:
            return out
        longest = _longest_string(out)
        if not longest or longest[0] <= 120:
            break
        parent, key = _get(out, longest[1][:-1]), longest[1][-1]
        parent[key] = parent[key][: max(100, longest[0] // 2)] + "…"
    for _ in range(2000):
        if _size(out) <= limit:
            return out
        lst = _longest_list(out)
        if not lst or lst[0] == 0:
            break
        _get(out, lst[1]).pop()
    keep = {k: out[k] for k in ("status", "reason", "client", "sources", "correlation_id") if k in out}
    keep.update({"truncated": True, "truncation_message": "The result was too large to return within the output budget."})
    return keep


def audited(tool: str):
    """Every tool call leaves an audit line, including when it fails unexpectedly."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(self: "Handover", principal: Principal | None, *args, **kwargs):
            raw_ref = kwargs.get("client_ref") or (args[0] if args and tool != "resolve_client" else None)
            ctx = self._ctx(tool, principal, self._canonical(raw_ref))
            try:
                out = await fn(self, ctx, principal, *args, **kwargs)
                return enforce_budget(out, self.budgets.max_output_chars)
            except AuditUnavailable:
                print(f"audit unavailable: {tool} {ctx['cid']}", file=sys.stderr)
                return {"status": "error", "reason": "audit_unavailable", "correlation_id": ctx["cid"],
                        "message": "The audit log could not be written, so no data is returned."}
            except Exception as exc:  # noqa: BLE001 - fail closed, audit without content
                try:
                    self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=ctx.get("client_ref"),
                                      tool=tool, decision="error", reason=f"internal_error:{type(exc).__name__}",
                                      policy_version=self._policy_version())
                except Exception:  # noqa: BLE001
                    print(f"audit unavailable: {tool} {ctx['cid']}", file=sys.stderr)
                return {"status": "error", "reason": "internal_error", "correlation_id": ctx["cid"],
                        "message": "The connector hit an unexpected error; nothing was returned. Quote the correlation_id."}
        return wrapper
    return deco


@dataclass
class Handover:
    policy: Policy
    credentials: CredentialStore
    connectwise: ConnectWise
    itglue: ITGlue
    cursors: CursorCodec
    audit: AuditLog
    budgets: Budgets
    clock_iso: Callable[[], str] = _now_iso

    # ------------------------------------------------------------------ helpers
    def _policy_version(self) -> str:
        try:
            return self.policy.version
        except Exception:  # noqa: BLE001
            return "unreadable"

    def _canonical(self, value: Any) -> str | None:
        try:
            return self.policy.canonical_client_ref(value)
        except Exception:  # noqa: BLE001
            return None

    def _refusal(self, ctx: dict, err: PolicyError, source_ids: list[str] | None = None) -> dict:
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=ctx.get("client_ref"),
            tool=ctx["tool"], decision="refused", reason=err.code, policy_version=self._policy_version(),
            source_ids=source_ids,
        )
        return {"status": "refused", "reason": err.code, "message": err.message, "correlation_id": ctx["cid"]}

    def _ctx(self, tool: str, principal: Principal | None, client_ref: str | None) -> dict:
        return {"tool": tool, "principal": principal.key if principal else None, "client_ref": client_ref,
                "cid": self.audit.new_correlation_id()}

    def _grant_and_link(self, principal: Principal | None, client_ref: str) -> tuple[Grant, ClientLink]:
        grant = self.policy.grant(principal)
        return grant, self.policy.link(grant, client_ref)

    def _source(self, system: str, record: str) -> dict:
        return {"system": system, "record": record, "fetched_at": self.clock_iso()}

    # ------------------------------------------------------------ resolve_client
    @audited("resolve_client")
    async def resolve_client(self, ctx: dict, principal: Principal | None, query: str) -> dict:
        try:
            grant = self.policy.grant(principal)
            if not isinstance(query, str) or len(query) > MAX_QUERY_CHARS:
                raise PolicyError("argument_too_long", "The query is too long.")
        except PolicyError as err:
            return self._refusal(ctx, err)
        q = query.strip().casefold()
        visible = [l for l in self.policy.all_links() if l.client_ref in grant.clients]
        exact_ref = [l for l in visible if l.client_ref.casefold() == q]
        matches = exact_ref or [l for l in visible if q and q in l.display_name.casefold()]
        candidates = [
            {"client_ref": l.client_ref, "display_name": l.display_name,
             "psa_company_id": l.psa_company_id, "itglue_organization_id": l.itglue_organization_id}
            for l in matches
        ]
        names = [c["display_name"].casefold() for c in candidates]
        out: dict[str, Any] = {"status": "ok", "candidates": candidates, "correlation_id": ctx["cid"]}
        if not candidates:
            out["status"] = "no_match"
            out["message"] = "No client you are authorized for matches this name or reference."
        elif len(candidates) > 1:
            out["status"] = "ambiguous"
            same = len(set(names)) < len(names)
            out["message"] = (
                "Several clients match" + (" and some share the same display name" if same else "")
                + ". Ask which client_ref is meant; nothing is looked up until one is chosen."
            )
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=None, tool=ctx["tool"],
            decision=out["status"], reason="resolved" if out["status"] == "ok" else out["status"],
            policy_version=self._policy_version(), source_ids=[f"policy:{c['client_ref']}" for c in candidates],
        )
        return out

    # --------------------------------------------------------- list_open_tickets
    @audited("list_open_tickets")
    async def list_open_tickets(self, ctx: dict, principal: Principal | None, client_ref: str, cursor: str | None = None) -> dict:
        deadline = Deadline.after(self.budgets.tool_deadline_s)
        query_key = "open"
        try:
            grant, link = self._grant_and_link(principal, client_ref)
            cred = self.credentials.psa(grant.psa_credential)
            state = {"page": 1, "skip": 0}
            if cursor is not None and (not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_CHARS):
                raise PolicyError("invalid_cursor", "This cursor is malformed.")
            if cursor:
                state = self.cursors.decode(cursor, principal=grant.principal.key, client_ref=client_ref,
                                            tool=ctx["tool"], query=query_key)
            page, skip = int(state["page"]), int(state["skip"])
            if page < 1 or skip < 0:
                raise PolicyError("invalid_cursor", "This cursor is malformed.")
        except (PolicyError, KeyError, TypeError, ValueError) as err:
            if not isinstance(err, PolicyError):
                err = PolicyError("invalid_cursor", "This cursor is malformed.")
            return self._refusal(ctx, err)

        # Ticket list budget: leave room for the envelope around the tickets.
        list_budget = max(500, self.budgets.max_output_chars - 1500)
        tickets: list[dict] = []
        excluded = oversized = 0
        has_more = False
        next_state: dict | None = None
        unavailable: list[dict] = []
        pages_read = 0
        try:
            while True:
                if pages_read >= self.budgets.max_upstream_pages:
                    has_more, next_state = True, {"page": page, "skip": skip}
                    break
                rows, more = await self.connectwise.open_tickets(cred, link.psa_company_id, page, deadline)
                pages_read += 1
                stop = False
                for i, row in enumerate(rows):
                    if i < skip:
                        continue
                    if row["company_id"] != link.psa_company_id:
                        excluded += 1  # upstream returned a record outside the requested client
                        continue
                    if len(tickets) >= self.budgets.max_records:
                        has_more, next_state, stop = True, {"page": page, "skip": i}, True
                        break
                    row["source"] = self._source("connectwise", f"service/tickets/{row['id']}")
                    if _size(tickets + [row]) > list_budget:
                        if not tickets:
                            oversized += 1  # cannot fit even alone: skipped and flagged, the cursor moves past it
                            continue
                        has_more, next_state, stop = True, {"page": page, "skip": i}, True
                        break
                    tickets.append(row)
                if stop:
                    break
                skip = 0
                if not more or not rows:
                    break
                page += 1
        except SourceUnavailable as err:
            unavailable.append(err.public())

        out: dict[str, Any] = {
            "status": "partial" if unavailable else "ok",
            "client": {"client_ref": link.client_ref, "display_name": link.display_name},
            "tickets": tickets,
            "has_more": has_more,
            "sources": [unavailable[0] if unavailable else {"system": "connectwise", "status": "ok"}],
            "correlation_id": ctx["cid"],
        }
        if has_more and next_state:
            out["cursor"] = self.cursors.encode(principal=grant.principal.key, client_ref=client_ref,
                                                tool=ctx["tool"], query=query_key, state=next_state)
            out["message"] = "More open tickets may exist. Call again with this cursor."
        if unavailable:
            out["message"] = ("ConnectWise could not be fully read; the list below is incomplete, "
                              "not a statement that the client has no other open tickets.")
        if excluded:
            out["excluded_out_of_scope_records"] = excluded
        if oversized:
            out["skipped_oversized_records"] = oversized
            out["truncated"] = True
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref, tool=ctx["tool"],
            decision="partial" if unavailable else "allowed", reason="ok" if not excluded else "out_of_scope_excluded",
            policy_version=self._policy_version(), source_ids=[f"cw:ticket/{t['id']}" for t in tickets],
            sources_unavailable=[u["system"] for u in unavailable],
        )
        return out

    # -------------------------------------------------------- get_ticket_context
    @audited("get_ticket_context")
    async def get_ticket_context(self, ctx: dict, principal: Principal | None, client_ref: str, ticket_id: int) -> dict:
        deadline = Deadline.after(self.budgets.tool_deadline_s)
        try:
            grant, link = self._grant_and_link(principal, client_ref)
            cred = self.credentials.psa(grant.psa_credential)
        except PolicyError as err:
            return self._refusal(ctx, err)

        sources: list[dict] = []
        source_ids: list[str] = []
        unavailable: list[str] = []
        out: dict[str, Any] = {"client": {"client_ref": link.client_ref, "display_name": link.display_name}}

        # 1. The ticket itself. If ConnectWise is down there is nothing to hand over.
        try:
            ticket = await self.connectwise.ticket(cred, ticket_id, deadline)
        except SourceUnavailable as err:
            self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                              tool=ctx["tool"], decision="failed", reason=f"connectwise_{err.code}",
                              policy_version=self._policy_version(), sources_unavailable=["connectwise"])
            return {"status": "unavailable", "sources": [err.public()], "correlation_id": ctx["cid"],
                    "message": "The ticket could not be read from ConnectWise; no handover can be prepared."}
        if ticket["id"] != int(ticket_id):
            return self._refusal(ctx, PolicyError(
                "upstream_record_mismatch", "ConnectWise returned a different ticket from the one requested; nothing is shown."),
                source_ids=[f"requested:cw:ticket/{int(ticket_id)}", f"received:cw:ticket/{ticket['id']}"])
        if ticket["company_id"] != link.psa_company_id:
            return self._refusal(ctx, PolicyError(
                "ticket_not_in_client", "This ticket does not belong to the requested client."))
        ticket["source"] = self._source("connectwise", f"service/tickets/{ticket_id}")
        out["ticket"] = ticket
        source_ids.append(f"cw:ticket/{ticket_id}")

        # 2. History and the PSA configurations attached to the ticket.
        psa_config_ids: list[int] = []
        try:
            notes = await self.connectwise.notes(cred, ticket_id, deadline, self.budgets)
            for n in notes:
                n["source"] = self._source("connectwise", f"service/tickets/{ticket_id}/notes/{n['id']}")
                source_ids.append(f"cw:note/{n['id']}")
            out["history"] = notes
            configs = await self.connectwise.ticket_configurations(cred, ticket_id, deadline)
            psa_config_ids = [c["id"] for c in configs]
            sources.append({"system": "connectwise", "status": "ok"})
        except SourceUnavailable as err:
            sources.append(err.public())
            unavailable.append("connectwise")

        # 3. IT Glue: configurations concerned (joined by PSA id, never by name) and site summary.
        try:
            org = await self.itglue.organization(link.itglue_organization_id, deadline)
            if org["id"] != link.itglue_organization_id:
                raise SourceUnavailable("itglue", "unexpected_record", "IT Glue returned a different organization.")
            documented, excluded_cfg, more_cfg = await self.itglue.configurations_for_psa_ids(
                link.itglue_organization_id, psa_config_ids, deadline)
            for c in documented:
                c["source"] = self._source("itglue", f"configurations/{c['id']}")
                source_ids.append(f"itg:configuration/{c['id']}")
            out["configurations"] = documented
            if more_cfg:
                out["configurations_has_more"] = True
            summary = await self.itglue.site_summary(link.itglue_organization_id, deadline)
            if summary is not None and summary.get("status") == "ambiguous":
                out["site_summary"] = summary
            elif summary is not None:
                summary["source"] = self._source("itglue", f"flexible_assets/{summary['id']}")
                source_ids.append(f"itg:flexible_asset/{summary['id']}")
                out["site_summary"] = summary
            if excluded_cfg:
                out["excluded_out_of_scope_records"] = excluded_cfg
            sources.append({"system": "itglue", "status": "ok"})
        except SourceUnavailable as err:
            sources.append(err.public())
            unavailable.append("itglue")

        # 4. Runbooks approved by the policy for this technician and client (ids and titles only).
        out["approved_documents"] = [
            {**d, "source": {"system": "policy", "record": f"policy/{self._policy_version()}"}}
            for d in self.policy.approved_documents(grant, client_ref)
        ]
        out["sources"] = sources
        if unavailable:
            out["status"] = "partial"
            out["message"] = (
                "Some sources could not be consulted: " + ", ".join(unavailable)
                + ". Facts from those systems are missing, not absent. Say so in the handover."
            )
        else:
            out["status"] = "ok"
        out["correlation_id"] = ctx["cid"]
        self._fit_history(out)
        self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                          tool=ctx["tool"], decision="partial" if unavailable else "allowed", reason="ok",
                          policy_version=self._policy_version(), source_ids=source_ids, sources_unavailable=unavailable)
        return out

    def _fit_history(self, out: dict) -> None:
        """Before the generic budget applies, drop the oldest history first: it matters least in a handover."""
        history = out.get("history") or []
        dropped = 0
        while len(history) > 1 and _size(out) > self.budgets.max_output_chars:
            history.pop(0)
            dropped += 1
        if dropped:
            out["history_truncated"] = {"dropped_oldest_notes": dropped,
                                        "message": "Older notes were left out to stay within the output budget."}

    # ------------------------------------------------------ get_document_excerpt
    @audited("get_document_excerpt")
    async def get_document_excerpt(self, ctx: dict, principal: Principal | None, client_ref: str, document_id: int) -> dict:
        deadline = Deadline.after(self.budgets.tool_deadline_s)
        try:
            grant, link = self._grant_and_link(principal, client_ref)
            if not self.policy.document_allowed(grant, client_ref, document_id):
                raise PolicyError("document_not_allowed", "This document is not approved for you in this client.")
        except PolicyError as err:
            return self._refusal(ctx, err)
        try:
            doc = await self.itglue.document_excerpt(link.itglue_organization_id, document_id, deadline, self.budgets)
        except DocumentRestricted:
            return self._refusal(ctx, PolicyError("document_restricted_in_itglue", "This document is restricted in IT Glue."))
        except RecordMismatch as mm:
            return self._refusal(ctx, PolicyError(
                "upstream_record_mismatch", "IT Glue returned a different record from the one requested; nothing is shown."),
                source_ids=[f"requested:{mm.requested}", f"received:{mm.received}"])
        except SourceUnavailable as err:
            self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                              tool=ctx["tool"], decision="failed", reason=f"itglue_{err.code}",
                              policy_version=self._policy_version(), sources_unavailable=["itglue"])
            return {"status": "unavailable", "sources": [err.public()], "correlation_id": ctx["cid"],
                    "message": "IT Glue could not be consulted; the document may exist but was not read."}
        doc["source"] = self._source("itglue", f"organizations/{link.itglue_organization_id}/relationships/documents/{document_id}")
        self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                          tool=ctx["tool"], decision="allowed", reason="ok", policy_version=self._policy_version(),
                          source_ids=[f"itg:document/{document_id}"])
        return {"status": "ok", "client": {"client_ref": link.client_ref, "display_name": link.display_name},
                "document": doc, "sources": [{"system": "itglue", "status": "ok"}], "correlation_id": ctx["cid"]}
