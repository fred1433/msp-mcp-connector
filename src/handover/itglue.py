"""IT Glue adapter (read-only, password-free by construction).

Three locks on passwords, each tested:
1. No code path calls a password endpoint or asks to include password relationships.
2. Every output is built from an allowlist of attributes; unknown attributes are dropped.
3. Flexible asset traits are kept only if the field definition says they are a
   safe kind. `Password` fields and `Tag` fields pointing at passwords are
   excluded. If the field definitions cannot be loaded, all traits are omitted.

A fourth lock belongs to the deployment, not the code: generate the IT Glue API
key without password access (docs/authorization.md). Fixtures cannot prove that
setting on a real key; it stays an acceptance task.
"""

from __future__ import annotations

import html
import re
from typing import Any

import httpx

from .config import Budgets
from .content import clean_free_text
from .upstream import Deadline, SharedBudget, SourceUnavailable, send

JSONAPI = "application/vnd.api+json"

CONFIGURATION_ATTRIBUTES = {
    "name": "name",
    "hostname": "hostname",
    "configuration-type-name": "type",
    "configuration-status-name": "status",
    "serial-number": "serial_number",
    "primary-ip": "primary_ip",
    "operating-system-name": "operating_system",
    "updated-at": "updated_at",
}

SAFE_TRAIT_KINDS = {"Text", "Number", "Date", "Select", "Checkbox", "Percent"}
FREE_TEXT_KINDS = {"Textbox"}  # passed through the content policy
SITE_SUMMARY_TYPE_ID = 41  # synthetic flexible asset type "Site Summary" in the fixtures; configurable


class ITGlue:
    system = "itglue"

    def __init__(self, base_url: str, api_key: str, http: httpx.AsyncClient, budget: SharedBudget,
                 budgets: Budgets, sleep=None, site_summary_type_id: int = SITE_SUMMARY_TYPE_ID) -> None:
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
            raise SourceUnavailable(self.system, "bad_response", "The source returned a body that is not JSON.") from None
        if not isinstance(body, dict) or "data" not in body:
            raise SourceUnavailable(self.system, "bad_response", "The source returned an unexpected shape.")
        return body

    # ------------------------------------------------------------------ reads
    async def organization(self, org_id: int, deadline: Deadline) -> dict:
        body = await self._get(f"/organizations/{int(org_id)}", {}, deadline)
        data = body["data"]
        return {"id": int(data["id"]), "name": (data.get("attributes") or {}).get("name")}

    async def configurations_for_psa_ids(self, org_id: int, psa_ids: list[int], deadline: Deadline) -> tuple[list[dict], int]:
        """IT Glue configurations of this organization synced from the ticket's PSA configurations.
        Joined by PSA id through filter[psa_id] + filter[psa_integration_type]=manage, never by name.
        Returns (configurations, excluded_out_of_scope)."""
        out, excluded, seen = [], 0, set()
        for psa_id in psa_ids:
            body = await self._get("/configurations", {
                "filter[organization_id]": int(org_id),
                "filter[psa_id]": str(int(psa_id)),
                "filter[psa_integration_type]": "manage",
            }, deadline)
            rows = body["data"] if isinstance(body["data"], list) else [body["data"]]
            for row in rows:
                if not isinstance(row, dict) or "id" not in row:
                    continue
                attrs = row.get("attributes") or {}
                if str(attrs.get("organization-id")) != str(org_id):
                    excluded += 1  # upstream returned a record from another organization
                    continue
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                item = {"id": int(row["id"]), "psa_configuration_id": int(psa_id)}
                for src, dst in CONFIGURATION_ATTRIBUTES.items():
                    if attrs.get(src) not in (None, ""):
                        item[dst] = attrs[src]
                out.append(item)
        return out, excluded

    async def _field_definitions(self, type_id: int, deadline: Deadline) -> dict[str, dict] | None:
        try:
            body = await self._get(f"/flexible_asset_types/{int(type_id)}/relationships/flexible_asset_fields", {}, deadline)
        except SourceUnavailable:
            return None
        defs = {}
        for row in body["data"]:
            a = row.get("attributes") or {}
            if a.get("name-key"):
                defs[a["name-key"]] = {"kind": a.get("kind"), "tag_type": a.get("tag-type"), "name": a.get("name")}
        return defs

    async def site_summary(self, org_id: int, deadline: Deadline) -> dict | None:
        body = await self._get("/flexible_assets", {
            "filter[flexible-asset-type-id]": self.site_summary_type_id,
            "filter[organization-id]": int(org_id),
        }, deadline)
        data = body["data"] if isinstance(body["data"], list) else [body["data"]]
        rows = [r for r in data if isinstance(r, dict) and str((r.get("attributes") or {}).get("organization-id")) == str(org_id)]
        if not rows:
            return None
        row = rows[0]
        attrs = row.get("attributes") or {}
        traits = attrs.get("traits") or {}
        defs = await self._field_definitions(self.site_summary_type_id, deadline)
        out: dict[str, Any] = {"id": int(row["id"]), "name": attrs.get("name"), "updated_at": attrs.get("updated-at")}
        if defs is None:
            out["fields"] = {}
            out["fields_omitted"] = {"reason": "field_definitions_unavailable", "count": len(traits)}
            return out
        fields: dict[str, Any] = {}
        excluded_password = 0
        excluded_other = 0
        for key, value in traits.items():
            d = defs.get(key)
            if d is None:
                excluded_other += 1  # not in the schema: unknown, so not shown
                continue
            kind = d["kind"]
            if kind == "Password" or (kind == "Tag" and str(d.get("tag_type", "")).lower() == "passwords"):
                excluded_password += 1
                continue
            label = d.get("name") or key
            if kind in SAFE_TRAIT_KINDS:
                fields[label] = value
            elif kind in FREE_TEXT_KINDS:
                fields[label] = clean_free_text(str(value), self.budgets.max_note_chars)[0]
            elif kind == "Tag":
                values = value.get("values") if isinstance(value, dict) else None
                fields[label] = [v.get("name") for v in values or [] if isinstance(v, dict)]
            else:
                excluded_other += 1
        out["fields"] = fields
        if excluded_password or excluded_other:
            out["fields_omitted"] = {"password_fields": excluded_password, "other_fields": excluded_other}
        return out

    async def document_excerpt(self, org_id: int, document_id: int, deadline: Deadline, budgets: Budgets) -> dict:
        """One request: the show route returns the document with its sections."""
        body = await self._get(f"/organizations/{int(org_id)}/relationships/documents/{int(document_id)}", {}, deadline)
        data = body["data"]
        attrs = data.get("attributes") or {}
        if attrs.get("restricted"):
            raise DocumentRestricted()
        parts = []
        for section in attrs.get("sections") or []:
            a = section.get("attributes", section) if isinstance(section, dict) else {}
            if a.get("resource-type") in ("Document::Heading", "Document::Text", "Document::Step"):
                parts.append(_strip_html(str(a.get("content") or "")))
        excerpt, modified = clean_free_text("\n".join(p for p in parts if p), budgets.max_note_chars)
        out = {"id": int(data["id"]), "organization_id": int(attrs.get("organization-id", -1)),
               "name": attrs.get("name"), "updated_at": attrs.get("updated-at"), "excerpt": excerpt}
        if modified:
            out["content_policy_applied"] = True
        return out


class DocumentRestricted(Exception):
    """IT Glue marks the document restricted: never excerpted, whatever the policy says."""


_TAG = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    text = re.sub(r"(?i)<br\s*/?>|</p>|</h\d>|</li>", "\n", text)
    return html.unescape(_TAG.sub("", text)).strip()
