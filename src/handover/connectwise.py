"""ConnectWise PSA adapter (read-only).

Request shapes (Basic auth `companyId+publicKey:privateKey`, `clientId` header,
`page` / `pageSize` / `conditions` / `orderBy`) come from public third-party
implementations, linked in docs/api-assumptions.md. The vendor's own reference
sits behind a developer login and is not quoted here.

Output is built field by field with typed parsers (src/handover/fields.py).
Anything not listed is dropped; a value of the wrong type is omitted and reported.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from .config import Budgets
from .credentials import PsaCredential
from .fields import Record, as_id
from .upstream import Deadline, SharedBudget, SourceUnavailable, send


def _bad(detail: str) -> SourceUnavailable:
    return SourceUnavailable("connectwise", "bad_response", detail)


def _sub(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else None


class ConnectWise:
    system = "connectwise"

    def __init__(self, base_url: str, client_id: str, http: httpx.AsyncClient, budget: SharedBudget,
                 budgets: Budgets, sleep=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.http = http
        self.budget = budget
        self.budgets = budgets
        self._sleep = sleep

    def _headers(self, cred: PsaCredential) -> dict:
        token = base64.b64encode(f"{cred.company_id}+{cred.public_key}:{cred.private_key}".encode()).decode()
        return {"Authorization": f"Basic {token}", "clientId": self.client_id, "Accept": "application/json"}

    async def _get(self, cred: PsaCredential, path: str, params: dict, deadline: Deadline) -> httpx.Response:
        request = self.http.build_request("GET", f"{self.base_url}{path}", params=params, headers=self._headers(cred))
        kw = {"sleep": self._sleep} if self._sleep else {}
        return await send(self.http, request, system=self.system, budget=self.budget, deadline=deadline,
                          timeout_s=self.budgets.upstream_timeout_s, max_retries=self.budgets.max_retries,
                          max_retry_wait_s=self.budgets.max_retry_wait_s, max_bytes=self.budgets.max_upstream_bytes, **kw)

    @staticmethod
    def _json(resp: httpx.Response, kind: type) -> Any:
        try:
            body = resp.json()
        except ValueError:
            raise _bad("The source returned a body that is not JSON.") from None
        if not isinstance(body, kind):
            raise _bad("The source returned an unexpected shape.")
        return body

    @staticmethod
    def _ticket(row: Any) -> dict:
        if not isinstance(row, dict):
            raise _bad("The source returned a ticket that is not an object.")
        ticket_id = as_id(row.get("id"))
        company_id = as_id(_sub(row.get("company"), "id"))
        if ticket_id is None or company_id is None:
            raise _bad("The source returned a ticket with a malformed id.")
        info = row.get("_info")
        r = Record()
        r.out["id"] = ticket_id
        r.text("summary", row.get("summary"))
        r.text("board", _sub(row.get("board"), "name"))
        r.text("status", _sub(row.get("status"), "name"))
        r.text("priority", _sub(row.get("priority"), "name"))
        r.out["company_id"] = company_id
        r.text("company_identifier", _sub(row.get("company"), "identifier"))
        r.text("contact", _sub(row.get("contact"), "name"))
        r.text("owner", _sub(row.get("owner"), "identifier"))
        r.date("entered_at", _sub(info, "dateEntered"))
        r.date("last_updated", _sub(info, "lastUpdated"))
        return r.done()

    async def open_tickets(self, cred: PsaCredential, company_id: int, page: int, deadline: Deadline) -> tuple[list[dict], bool]:
        params = {
            "conditions": f"company/id={int(company_id)} and closedFlag=false",
            "orderBy": "id desc",
            "page": page,
            "pageSize": self.budgets.max_records,
        }
        resp = await self._get(cred, "/service/tickets", params, deadline)
        rows = self._json(resp, list)
        # Next-page signal: a Link header with rel="next" (third-party source, see docs/api-assumptions.md),
        # or, failing that, a full page. A full last page costs one extra empty request, never a missed one.
        more = 'rel="next"' in resp.headers.get("link", "") or len(rows) >= self.budgets.max_records
        return [self._ticket(r) for r in rows], more

    async def ticket(self, cred: PsaCredential, ticket_id: int, deadline: Deadline) -> dict:
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}", {}, deadline)
        return self._ticket(self._json(resp, dict))

    async def notes(self, cred: PsaCredential, ticket_id: int, deadline: Deadline, budgets: Budgets) -> list[dict]:
        params = {"orderBy": "id desc", "page": 1, "pageSize": budgets.max_notes}
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}/notes", params, deadline)
        out = []
        for row in self._json(resp, list):
            if not isinstance(row, dict):
                continue
            note_id = as_id(row.get("id"))
            if note_id is None:
                raise _bad("The source returned a note with a malformed id.")
            kind = ("resolution" if row.get("resolutionFlag") is True else
                    "internal" if row.get("internalAnalysisFlag") is True else
                    "discussion" if row.get("detailDescriptionFlag") is True else "note")
            r = Record()
            r.out["id"] = note_id
            r.out["kind"] = kind
            r.date("created_at", row.get("dateCreated"))
            r.text("created_by", row.get("createdBy"))
            r.text("text", row.get("text"), budgets.max_note_chars)
            out.append(r.done())
        out.sort(key=lambda n: n["id"])  # oldest first, so a reader follows the story
        return out

    async def ticket_configurations(self, cred: PsaCredential, ticket_id: int, deadline: Deadline) -> list[dict]:
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}/configurations", {}, deadline)
        out = []
        for row in self._json(resp, list):
            if not isinstance(row, dict):
                continue
            cid = as_id(row.get("id"))
            if cid is None:
                raise _bad("The source returned a configuration with a malformed id.")
            out.append({"id": cid})
        return out
