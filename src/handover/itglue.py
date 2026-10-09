"""IT Glue adapter (read-only, password-free by construction).

Locks on passwords, each tested:
1. No code path calls a password endpoint or asks to include password relationships.
2. Every output field is built from an allowlist with a typed parser (src/handover/fields.py);
   unknown attributes are dropped, values of the wrong type are omitted and reported.
3. Flexible asset traits are kept only if the field definition says they are a
   safe kind. `Password` fields and `Tag` fields pointing at passwords are
   excluded. If the field definitions cannot be read completely, all traits are omitted.
4. A field whose name suggests a secret (password, passcode, PIN, key, secret,
   credential, token...) is omitted whatever its kind.
5. Every string from IT Glue (names, Select values, Tag names, text traits,
   document sections) passes through the content policy (src/handover/content.py).

A last lock belongs to the deployment, not the code: generate the IT Glue API
key without password access (docs/authorization.md). Fixtures cannot prove that
setting on a real key; it stays an acceptance task.
"""

from __future__ import annotations

import html
import re
from typing import Any

import httpx

from .config import Budgets
from .content import name_suggests_secret
from .fields import Record, as_id
from .upstream import Deadline, SharedBudget, SourceUnavailable, send

JSONAPI = "application/vnd.api+json"
FIELD_DEFINITION_PAGE_SIZE = 100
FIELD_DEFINITION_MAX_PAGES = 5

# attribute -> (output key, parser)
CONFIGURATION_ATTRIBUTES = {
    "name": ("name", "text"),
    "hostname": ("hostname", "text"),
    "configuration-type-name": ("type", "text"),
    "configuration-status-name": ("status", "text"),
    "serial-number": ("serial_number", "text"),
    "primary-ip": ("primary_ip", "text"),
    "operating-system-name": ("operating_system", "text"),
    "updated-at": ("updated_at", "date"),
}

SCALAR_TRAIT_KINDS = {"Number", "Percent", "Checkbox"}
TEXT_TRAIT_KINDS = {"Text", "Textbox", "Select"}
DATE_TRAIT_KINDS = {"Date"}


class DocumentRestricted(Exception):
    """IT Glue marks the document restricted: never excerpted, whatever the policy says."""


class RecordMismatch(Exception):
    """The upstream returned a different record from the one requested."""

    def __init__(self, requested: str, received: str) -> None:
        super().__init__("record mismatch")
        self.requested = requested
        self.received = received


_TAG = re.compile(r"<[^>]{0,2000}>")


def _strip_html(text: str) -> str:
    text = re.sub(r"(?i)<br ?/?>|</p>|</h[1-6]>|</li>", "\n", text)
    return html.unescape(_TAG.sub("", text)).strip()


def _bad(detail: str) -> SourceUnavailable:
    return SourceUnavailable("itglue", "bad_response", detail)


class ITGlue:
    system = "itglue"

    def __init__(self, base_url: str, api_key: str, http: httpx.AsyncClient, budget: SharedBudget,
                 budgets: Budgets, sleep=None, site_summary_type_id: int | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.http = http
        self.budget = budget
        self.budgets = budgets
        self._sleep = sleep
        self.site_summary_type_id = site_summary_type_id

    async def _get(self, path: str, params: dict, deadline: Deadline) -> dict:
        if "password" in path:
            raise AssertionError("password endpoints are never called")
        request = self.http.build_request(
            "GET", f"{self.base_url}{path}", params=params,
            headers={"x-api-key": self.api_key, "Content-Type": JSONAPI, "Accept": JSONAPI},
        )
        kw = {"sleep": self._sleep} if self._sleep else {}
        resp = await send(self.http, request, system=self.system, budget=self.budget, deadline=deadline,
                          timeout_s=self.budgets.upstream_timeout_s, max_retries=self.budgets.max_retries,
                          max_retry_wait_s=self.budgets.max_retry_wait_s, max_bytes=self.budgets.max_upstream_bytes, **kw)
        try:
            body = resp.json()
        except ValueError:
            raise _bad("The source returned a body that is not JSON.") from None
        if not isinstance(body, dict) or "data" not in body:
            raise _bad("The source returned an unexpected shape.")
        return body

    @staticmethod
    def _rows(body: dict) -> list[dict]:
        data = body["data"]
        rows = data if isinstance(data, list) else [data]
        return [r for r in rows if isinstance(r, dict)]

    @staticmethod
    def _attrs(row: dict) -> dict:
        a = row.get("attributes")
        return a if isinstance(a, dict) else {}

    @staticmethod
    def _next_page(body: dict) -> Any:
        meta = body.get("meta")
        return meta.get("next-page") if isinstance(meta, dict) else None

    # ------------------------------------------------------------------ reads
    async def organization(self, org_id: int, deadline: Deadline) -> dict:
        body = await self._get(f"/organizations/{int(org_id)}", {}, deadline)
        data = body["data"]
        oid = as_id(data.get("id")) if isinstance(data, dict) else None
        if oid is None:
            raise _bad("The organization record has no valid id.")
        return {"id": oid}

    async def configurations_for_psa_ids(self, org_id: int, psa_ids: list[int], deadline: Deadline) -> tuple[list[dict], int, bool]:
        """IT Glue configurations of this organization synced from the ticket's PSA configurations.
        Joined by PSA id through filter[psa_id] + filter[psa_integration_type]=manage, never by name.
        The accumulated list is bounded to `max_records`.
        Returns (configurations, excluded_out_of_scope, has_more)."""
        out: list[dict] = []
        excluded, seen, more = 0, set(), False
        for psa_id in psa_ids:
            if len(out) >= self.budgets.max_records:
                more = True
                break
            body = await self._get("/configurations", {
                "filter[organization_id]": int(org_id),
                "filter[psa_id]": str(int(psa_id)),
                "filter[psa_integration_type]": "manage",
            }, deadline)
            if self._next_page(body):
                more = True
            for row in self._rows(body):
                cid = as_id(row.get("id"))
                if cid is None or cid in seen:
                    continue
                attrs = self._attrs(row)
                if as_id(attrs.get("organization-id")) != int(org_id):
                    excluded += 1  # upstream returned a record from another organization
                    continue
                if len(out) >= self.budgets.max_records:
                    more = True
                    break
                seen.add(cid)
                r = Record()
                r.out["id"] = cid
                r.out["psa_configuration_id"] = int(psa_id)
                for src, (dst, kind) in CONFIGURATION_ATTRIBUTES.items():
                    (r.text if kind == "text" else r.date)(dst, attrs.get(src))
                out.append(r.done())
        return out, excluded, more

    async def _field_definitions(self, type_id: int, deadline: Deadline) -> tuple[dict[str, dict] | None, str | None]:
        """All field definitions of a flexible asset type, following pages. (defs, problem)."""
        defs: dict[str, dict] = {}
        page = 1
        while True:
            try:
                body = await self._get(f"/flexible_asset_types/{int(type_id)}/relationships/flexible_asset_fields",
                                       {"page[size]": FIELD_DEFINITION_PAGE_SIZE, "page[number]": page}, deadline)
            except SourceUnavailable:
                return None, "field_definitions_unavailable"
            for row in self._rows(body):
                a = self._attrs(row)
                key = a.get("name-key")
                if isinstance(key, str):
                    defs[key] = {"kind": a.get("kind"), "tag_type": a.get("tag-type"), "name": a.get("name")}
            if not self._next_page(body):
                return defs, None
            if page >= FIELD_DEFINITION_MAX_PAGES:
                return None, "field_definitions_incomplete"
            page += 1

    async def site_summary(self, org_id: int, deadline: Deadline) -> dict | None:
        if self.site_summary_type_id is None:
            return None
        body = await self._get("/flexible_assets", {
            "filter[flexible-asset-type-id]": int(self.site_summary_type_id),
            "filter[organization-id]": int(org_id),
        }, deadline)
        rows = [r for r in self._rows(body) if as_id(self._attrs(r).get("organization-id")) == int(org_id)
                and as_id(r.get("id")) is not None]
        if not rows:
            return None
        if len(rows) > 1 or self._next_page(body):
            return {"status": "ambiguous", "candidate_ids": sorted(as_id(r["id"]) for r in rows),
                    "message": "Several site summaries exist for this organization; none is shown. "
                               "Configure which one is authoritative."}
        row = rows[0]
        attrs = self._attrs(row)
        traits = attrs.get("traits") if isinstance(attrs.get("traits"), dict) else {}
        head = Record()
        head.out["id"] = as_id(row["id"])
        head.text("name", attrs.get("name"))
        head.date("updated_at", attrs.get("updated-at"))
        out = head.done()
        defs, problem = await self._field_definitions(self.site_summary_type_id, deadline)
        if defs is None:
            out["fields"] = {}
            out["fields_omitted"] = {"reason": problem, "count": len(traits)}
            return out
        fields = Record()
        omitted = {"password_fields": 0, "secret_named_fields": 0, "other_fields": 0}
        for key, value in traits.items():
            d = defs.get(key)
            if d is None:
                omitted["other_fields"] += 1  # not in the schema: unknown, so not shown
                continue
            kind, tag_type, name = d["kind"], d.get("tag_type"), d.get("name")
            if kind == "Password" or (kind == "Tag" and isinstance(tag_type, str) and tag_type.lower() == "passwords"):
                omitted["password_fields"] += 1
                continue
            if not isinstance(name, str) or name_suggests_secret(name, key):
                omitted["secret_named_fields" if isinstance(name, str) else "other_fields"] += 1
                continue
            label = name[:100]
            if kind in TEXT_TRAIT_KINDS:
                fields.text(label, value, self.budgets.max_note_chars)
            elif kind in SCALAR_TRAIT_KINDS:
                fields.scalar(label, value)
            elif kind in DATE_TRAIT_KINDS:
                fields.date(label, value)
            elif kind == "Tag" and isinstance(value, dict) and isinstance(value.get("values"), list):
                names = [v.get("name") for v in value["values"] if isinstance(v, dict)]
                fields.text_list(label, names, self.budgets.max_records)
            else:
                omitted["other_fields"] += 1
        built = fields.done()
        for flag in ("omitted_malformed_fields", "content_policy_applied", "truncated_fields"):
            if flag in built:
                out[flag] = built.pop(flag)
        out["fields"] = built
        omitted = {k: v for k, v in omitted.items() if v}
        if omitted:
            out["fields_omitted"] = omitted
        return out

    async def document_excerpt(self, org_id: int, document_id: int, deadline: Deadline, budgets: Budgets) -> dict:
        """One request: the show route returns the document with its sections.
        The record received must be a document, with the id requested, in the organization requested."""
        body = await self._get(f"/organizations/{int(org_id)}/relationships/documents/{int(document_id)}", {}, deadline)
        data = body["data"]
        if not isinstance(data, dict):
            raise _bad("The document record is not an object.")
        received_id = as_id(data.get("id"))
        attrs = self._attrs(data)
        received_org = as_id(attrs.get("organization-id"))
        if data.get("type") != "documents" or received_id != int(document_id) or received_org != int(org_id):
            raise RecordMismatch(f"itg:document/{int(document_id)}",
                                 f"itg:{'document' if data.get('type') == 'documents' else 'other'}/{received_id}")
        if attrs.get("restricted") is not False:
            raise DocumentRestricted()  # restricted, or the flag is missing or not a boolean: fail closed
        parts = []
        sections = attrs.get("sections") if isinstance(attrs.get("sections"), list) else []
        for section in sections:
            a = section.get("attributes", section) if isinstance(section, dict) else {}
            if isinstance(a, dict) and a.get("resource-type") in ("Document::Heading", "Document::Text", "Document::Step"):
                content = a.get("content")
                if isinstance(content, str):
                    parts.append(_strip_html(content[:50_000]))
        r = Record()
        r.out["id"] = received_id
        r.out["organization_id"] = received_org
        r.text("name", attrs.get("name"))
        r.date("updated_at", attrs.get("updated-at"))
        r.text("excerpt", "\n".join(p for p in parts if p), budgets.max_note_chars)
        return r.done()
