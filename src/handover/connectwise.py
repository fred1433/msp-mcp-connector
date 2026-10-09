"""ConnectWise PSA adapter (read-only).

Request shapes (Basic auth `companyId+publicKey:privateKey`, `clientId` header,
`page` / `pageSize` / `conditions` / `orderBy`) come from public third-party
implementations, linked in docs/api-assumptions.md. The vendor's own reference
sits behind a developer login and is not quoted here.

Output is built field by field from allowlists. Anything not listed is dropped.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from .config import Budgets
from .content import clean_free_text
from .credentials import PsaCredential
from .upstream import Deadline, SharedBudget, SourceUnavailable, send


def _name(obj: Any, key: str = "name") -> str | None:
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
            raise SourceUnavailable("connectwise", "bad_response", "The source returned a body that is not JSON.") from None
        if not isinstance(body, kind):
            raise SourceUnavailable("connectwise", "bad_response", "The source returned an unexpected shape.")
        return body

    @staticmethod
    def _ticket(row: dict) -> dict:
        info = row.get("_info") or {}
        company = row.get("company") or {}
        return {
            "id": int(row["id"]),
            "summary": row.get("summary"),
            "board": _name(row.get("board")),
            "status": _name(row.get("status")),
            "priority": _name(row.get("priority")),
            "company_id": int(company.get("id", -1)),
            "company_identifier": company.get("identifier"),
            "contact": _name(row.get("contact")),
            "owner": _name(row.get("owner"), "identifier"),
            "entered_at": info.get("dateEntered"),
            "last_updated": info.get("lastUpdated"),
        }

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
        return [self._ticket(r) for r in rows if isinstance(r, dict) and "id" in r], more

    async def ticket(self, cred: PsaCredential, ticket_id: int, deadline: Deadline) -> dict:
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}", {}, deadline)
        return self._ticket(self._json(resp, dict))

    async def notes(self, cred: PsaCredential, ticket_id: int, deadline: Deadline, budgets: Budgets) -> list[dict]:
        params = {"orderBy": "id desc", "page": 1, "pageSize": budgets.max_notes}
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}/notes", params, deadline)
        out = []
        for row in self._json(resp, list):
            if not isinstance(row, dict) or "id" not in row:
                continue
            text, withheld = clean_free_text(str(row.get("text") or ""), budgets.max_note_chars)
            kind = ("resolution" if row.get("resolutionFlag") else
                    "internal" if row.get("internalAnalysisFlag") else
                    "discussion" if row.get("detailDescriptionFlag") else "note")
            note = {"id": int(row["id"]), "kind": kind, "created_at": row.get("dateCreated"),
                    "created_by": row.get("createdBy"), "text": text}
            if withheld:
                note["content_policy_applied"] = True
            out.append(note)
        out.sort(key=lambda n: n["id"])  # oldest first, so a reader follows the story
        return out

    async def ticket_configurations(self, cred: PsaCredential, ticket_id: int, deadline: Deadline) -> list[dict]:
        resp = await self._get(cred, f"/service/tickets/{int(ticket_id)}/configurations", {}, deadline)
        return [{"id": int(r["id"]), "name": r.get("deviceIdentifier") or r.get("name")}
                for r in self._json(resp, list) if isinstance(r, dict) and "id" in r]
