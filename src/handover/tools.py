"""The four read-only tools, independent of the MCP transport.

resolve_client      -> which client do you mean (by internal reference, never joined by name)
list_open_tickets   -> open PSA tickets for one client, paginated with a bound cursor
get_ticket_context  -> one ticket, its history, the IT Glue configurations it concerns,
                       and the client's site summary, each fact with its source
get_document_excerpt-> an approved excerpt of one IT Glue document

Every call: principal from the validated token, grant from the policy, client
link from the policy, upstream calls with that principal's PSA credentials,
output built from allowlists, one audit record.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .audit import AuditLog
from .config import Budgets
from .connectwise import ConnectWise
from .credentials import CredentialStore
from .cursor import CursorCodec
from .identity import Principal
from .itglue import DocumentRestricted, ITGlue
from .policy import ClientLink, Grant, Policy, PolicyError
from .upstream import Deadline, SourceUnavailable


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


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
    def _refusal(self, ctx: dict, err: PolicyError) -> dict:
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=ctx.get("client_ref"),
            tool=ctx["tool"], decision="refused", reason=err.code, policy_version=self.policy.version,
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
    async def resolve_client(self, principal: Principal | None, query: str) -> dict:
        ctx = self._ctx("resolve_client", principal, None)
        try:
            grant = self.policy.grant(principal)
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
        ambiguous = len(candidates) > 1
        out: dict[str, Any] = {"status": "ok", "candidates": candidates, "correlation_id": ctx["cid"]}
        if not candidates:
            out["status"] = "no_match"
            out["message"] = "No client you are authorized for matches this name or reference."
        elif ambiguous:
            out["status"] = "ambiguous"
            same = len(set(names)) < len(names)
            out["message"] = (
                "Several clients match" + (" and some share the same display name" if same else "")
                + ". Ask which client_ref is meant; nothing is looked up until one is chosen."
            )
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=None, tool=ctx["tool"],
            decision=out["status"], reason="resolved" if out["status"] == "ok" else out["status"],
            policy_version=self.policy.version, source_ids=[f"policy:{c['client_ref']}" for c in candidates],
        )
        return out

    # --------------------------------------------------------- list_open_tickets
    async def list_open_tickets(self, principal: Principal | None, client_ref: str, cursor: str | None = None) -> dict:
        ctx = self._ctx("list_open_tickets", principal, client_ref)
        deadline = Deadline.after(self.budgets.tool_deadline_s)
        query_key = "open"
        try:
            grant, link = self._grant_and_link(principal, client_ref)
            cred = self.credentials.psa(grant.psa_credential)
            state = {"page": 1, "skip": 0}
            if cursor:
                state = self.cursors.decode(cursor, principal=grant.principal.key, client_ref=client_ref,
                                            tool=ctx["tool"], query=query_key)
        except PolicyError as err:
            return self._refusal(ctx, err)

        tickets: list[dict] = []
        excluded = 0
        has_more = False
        next_state: dict | None = None
        page, skip = int(state["page"]), int(state["skip"])
        unavailable: list[dict] = []
        pages_read = 0
        try:
            while len(tickets) < self.budgets.max_records and pages_read < self.budgets.max_upstream_pages:
                rows, more = await self.connectwise.open_tickets(cred, link.psa_company_id, page, deadline)
                pages_read += 1
                for i, row in enumerate(rows):
                    if i < skip:
                        continue
                    if row["company_id"] != link.psa_company_id:
                        excluded += 1  # upstream returned a record outside the requested client
                        continue
                    row["source"] = self._source("connectwise", f"service/tickets/{row['id']}")
                    candidate = tickets + [row]
                    if len(candidate) > self.budgets.max_records or _size(candidate) > self.budgets.max_output_chars:
                        has_more, next_state = True, {"page": page, "skip": i}
                        break
                    tickets = candidate
                if next_state:
                    break
                skip = 0
                if not more:
                    break
                page += 1
                if len(tickets) >= self.budgets.max_records or pages_read >= self.budgets.max_upstream_pages:
                    has_more, next_state = True, {"page": page, "skip": 0}
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
            out["message"] = "More open tickets exist. Call again with this cursor, or narrow the request."
        if unavailable:
            out["message"] = ("ConnectWise could not be fully read; the list below is incomplete, "
                              "not a statement that the client has no other open tickets.")
        if excluded:
            out["excluded_out_of_scope_records"] = excluded
        self.audit.record(
            correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref, tool=ctx["tool"],
            decision="partial" if unavailable else "allowed", reason="ok" if not excluded else "out_of_scope_excluded",
            policy_version=self.policy.version, source_ids=[f"cw:ticket/{t['id']}" for t in tickets],
            sources_unavailable=[u["system"] for u in unavailable],
        )
        return out

    # -------------------------------------------------------- get_ticket_context
    async def get_ticket_context(self, principal: Principal | None, client_ref: str, ticket_id: int) -> dict:
        ctx = self._ctx("get_ticket_context", principal, client_ref)
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
                              policy_version=self.policy.version, sources_unavailable=["connectwise"])
            return {"status": "unavailable", "sources": [err.public()], "correlation_id": ctx["cid"],
                    "message": "The ticket could not be read from ConnectWise; no handover can be prepared."}
        if ticket["company_id"] != link.psa_company_id:
            return self._refusal(ctx, PolicyError(
                "ticket_not_in_client", f"Ticket {ticket_id} does not belong to client {client_ref}."))
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
            documented, excluded_cfg = await self.itglue.configurations_for_psa_ids(
                link.itglue_organization_id, psa_config_ids, deadline)
            for c in documented:
                c["source"] = self._source("itglue", f"configurations/{c['id']}")
                source_ids.append(f"itg:configuration/{c['id']}")
            out["configurations"] = documented
            summary = await self.itglue.site_summary(link.itglue_organization_id, deadline)
            if summary is not None:
                summary["source"] = self._source("itglue", f"flexible_assets/{summary['id']}")
                source_ids.append(f"itg:flexible_asset/{summary['id']}")
                out["site_summary"] = summary
            if excluded_cfg:
                out["excluded_out_of_scope_records"] = excluded_cfg
            sources.append({"system": "itglue", "status": "ok"})
        except SourceUnavailable as err:
            sources.append(err.public())
            unavailable.append("itglue")

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
        self._fit(out)
        self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                          tool=ctx["tool"], decision="partial" if unavailable else "allowed", reason="ok",
                          policy_version=self.policy.version, source_ids=source_ids, sources_unavailable=unavailable)
        return out

    def _fit(self, out: dict) -> None:
        """Keep the result under the output budget by dropping the oldest history first."""
        history = out.get("history") or []
        dropped = 0
        while history and _size(out) > self.budgets.max_output_chars:
            history.pop(0)
            dropped += 1
        if dropped:
            out["history_truncated"] = {"dropped_oldest_notes": dropped,
                                        "message": "Older notes were left out to stay within the output budget."}

    # ------------------------------------------------------ get_document_excerpt
    async def get_document_excerpt(self, principal: Principal | None, client_ref: str, document_id: int) -> dict:
        ctx = self._ctx("get_document_excerpt", principal, client_ref)
        deadline = Deadline.after(self.budgets.tool_deadline_s)
        try:
            grant, link = self._grant_and_link(principal, client_ref)
            if not self.policy.document_allowed(grant, client_ref, document_id):
                raise PolicyError("document_not_allowed",
                                  f"Document {document_id} is not approved for you in client {client_ref}.")
        except PolicyError as err:
            return self._refusal(ctx, err)
        try:
            doc = await self.itglue.document_excerpt(link.itglue_organization_id, document_id, deadline, self.budgets)
        except DocumentRestricted:
            return self._refusal(ctx, PolicyError("document_restricted_in_itglue",
                                                  f"Document {document_id} is restricted in IT Glue."))
        except SourceUnavailable as err:
            self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                              tool=ctx["tool"], decision="failed", reason=f"itglue_{err.code}",
                              policy_version=self.policy.version, sources_unavailable=["itglue"])
            return {"status": "unavailable", "sources": [err.public()], "correlation_id": ctx["cid"],
                    "message": "IT Glue could not be consulted; the document may exist but was not read."}
        if doc["organization_id"] != link.itglue_organization_id:
            return self._refusal(ctx, PolicyError("document_not_in_client",
                                                  f"Document {document_id} does not belong to client {client_ref}."))
        doc["source"] = self._source("itglue", f"organizations/{link.itglue_organization_id}/relationships/documents/{document_id}")
        self.audit.record(correlation_id=ctx["cid"], principal=ctx["principal"], client_ref=client_ref,
                          tool=ctx["tool"], decision="allowed", reason="ok", policy_version=self.policy.version,
                          source_ids=[f"itg:document/{document_id}"])
        return {"status": "ok", "client": {"client_ref": link.client_ref, "display_name": link.display_name},
                "document": doc, "sources": [{"system": "itglue", "status": "ok"}], "correlation_id": ctx["cid"]}


def query_fingerprint(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:16]
