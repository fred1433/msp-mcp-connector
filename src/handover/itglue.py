"""IT Glue adapter (read-only, password-free by construction).

Locks on passwords, each tested:
1. No code path calls a password endpoint or asks to include password relationships.
2. Every output is built from an allowlist of attributes; unknown attributes are dropped.
3. Flexible asset traits are kept only if the field definition says they are a
   safe kind. `Password` fields and `Tag` fields pointing at passwords are
   excluded. If the field definitions cannot be loaded, all traits are omitted.
4. A field whose name suggests a secret (password, passcode, PIN, key, secret,
   credential, token...) is omitted whatever its kind.
5. Every text value passes through the content policy (src/handover/content.py).

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
from .content import cap, clean, name_suggests_secret
from .upstream import Deadline, SharedBudget, SourceUnavailable, send

JSONAPI = "application/vnd.api+json"
MAX_ATTR_CHARS = 200

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

PLAIN_TRAIT_KINDS = {"Number", "Date", "Select", "Checkbox", "Percent"}
TEXT_TRAIT_KINDS = {"Text", "Textbox"}  # passed through the content policy


class DocumentRestricted(Exception):
    """IT Glue marks the document restricted: never excerpted, whatever the policy says."""


_TAG = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    text = re.sub(r"(?i)<br\s*/?>|</p>|</h\d>|</li>", "\n", text)
    return html.unescape(_TAG.sub("", text)).strip()


def _bad(detail: str) -> SourceUnavailable:
    return SourceUnavailable("itglue", "bad_response", detail)


def _int(value: Any, what: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise _bad(f"The source returned a {what} that is not a number.") from None


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

    # ------------------------------------------------------------------ reads
    async def organization(self, org_id: int, deadline: Deadline) -> dict:
        body = await self._get(f"/organizations/{int(org_id)}", {}, deadline)
        data = body["data"]
        if not isinstance(data, dict) or "id" not in data:
            raise _bad("The organization record has no id.")
        return {"id": _int(data["id"], "organization id"), "name": cap((data.get("attributes") or {}).get("name"), MAX_ATTR_CHARS)}

    async def configurations_for_psa_ids(self, org_id: int, psa_ids: list[int], deadline: Deadline) -> tuple[list[dict], int, bool]:
        """IT Glue configurations of this organization synced from the ticket's PSA configurations.
        Joined by PSA id through filter[psa_id] + filter[psa_integration_type]=manage, never by name.
        At most `max_records` PSA configurations are looked up.
        Returns (configurations, excluded_out_of_scope, more_not_looked_up)."""
        more = len(psa_ids) > self.budgets.max_records
        out, excluded, seen = [], 0, set()
        for psa_id in psa_ids[: self.budgets.max_records]:
            body = await self._get("/configurations", {
                "filter[organization_id]": int(org_id),
                "filter[psa_id]": str(int(psa_id)),
                "filter[psa_integration_type]": "manage",
            }, deadline)
            for row in self._rows(body):
                if "id" not in row:
                    continue
                attrs = row.get("attributes") or {}
                if str(attrs.get("organization-id")) != str(org_id):
                    excluded += 1  # upstream returned a record from another organization
                    continue
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                item: dict[str, Any] = {"id": _int(row["id"], "configuration id"), "psa_configuration_id": int(psa_id)}
                for src, dst in CONFIGURATION_ATTRIBUTES.items():
                    value = attrs.get(src)
                    if value not in (None, ""):
                        item[dst] = cap(str(value), MAX_ATTR_CHARS)
                out.append(item)
        return out, excluded, more

    async def _field_definitions(self, type_id: int, deadline: Deadline) -> dict[str, dict] | None:
        try:
            body = await self._get(f"/flexible_asset_types/{int(type_id)}/relationships/flexible_asset_fields", {}, deadline)
        except SourceUnavailable:
            return None
        defs = {}
        for row in self._rows(body):
            a = row.get("attributes") or {}
            if a.get("name-key"):
                defs[a["name-key"]] = {"kind": a.get("kind"), "tag_type": a.get("tag-type"), "name": a.get("name")}
        return defs

    async def site_summary(self, org_id: int, deadline: Deadline) -> dict | None:
        if self.site_summary_type_id is None:
            return None
        body = await self._get("/flexible_assets", {
            "filter[flexible-asset-type-id]": int(self.site_summary_type_id),
            "filter[organization-id]": int(org_id),
        }, deadline)
        rows = [r for r in self._rows(body) if str((r.get("attributes") or {}).get("organization-id")) == str(org_id)]
        if not rows or "id" not in rows[0]:
            return None
        row = rows[0]
        attrs = row.get("attributes") or {}
        traits = attrs.get("traits") if isinstance(attrs.get("traits"), dict) else {}
        defs = await self._field_definitions(self.site_summary_type_id, deadline)
        out: dict[str, Any] = {"id": _int(row["id"], "flexible asset id"), "name": cap(attrs.get("name"), MAX_ATTR_CHARS),
                               "updated_at": attrs.get("updated-at")}
        if defs is None:
            out["fields"] = {}
            out["fields_omitted"] = {"reason": "field_definitions_unavailable", "count": len(traits)}
            return out
        fields: dict[str, Any] = {}
        omitted = {"password_fields": 0, "secret_named_fields": 0, "other_fields": 0}
        redacted, truncated = [], []
        for key, value in traits.items():
            d = defs.get(key)
            if d is None:
                omitted["other_fields"] += 1  # not in the schema: unknown, so not shown
                continue
            kind = d["kind"]
            if kind == "Password" or (kind == "Tag" and str(d.get("tag_type") or "").lower() == "passwords"):
                omitted["password_fields"] += 1
                continue
            if name_suggests_secret(d.get("name"), key):
                omitted["secret_named_fields"] += 1
                continue
            label = cap(d.get("name") or key, MAX_ATTR_CHARS)
            if kind in TEXT_TRAIT_KINDS and isinstance(value, str):
                c = clean(value, self.budgets.max_note_chars)
                fields[label] = c.text
                if c.redacted:
                    redacted.append(label)
                if c.truncated:
                    truncated.append(label)
            elif kind in PLAIN_TRAIT_KINDS and isinstance(value, (int, float, bool)):
                fields[label] = value
            elif kind in PLAIN_TRAIT_KINDS and isinstance(value, str):
                fields[label] = cap(value, MAX_ATTR_CHARS)
            elif kind == "Tag" and isinstance(value, dict):
                names = [v.get("name") for v in value.get("values") or [] if isinstance(v, dict)]
                fields[label] = [cap(str(n), MAX_ATTR_CHARS) for n in names[: self.budgets.max_records] if n]
            else:
                omitted["other_fields"] += 1
        out["fields"] = fields
        omitted = {k: v for k, v in omitted.items() if v}
        if omitted:
            out["fields_omitted"] = omitted
        if redacted:
            out["content_policy_applied"] = redacted
        if truncated:
            out["truncated_fields"] = truncated
        return out

    async def document_excerpt(self, org_id: int, document_id: int, deadline: Deadline, budgets: Budgets) -> dict:
        """One request: the show route returns the document with its sections."""
        body = await self._get(f"/organizations/{int(org_id)}/relationships/documents/{int(document_id)}", {}, deadline)
        data = body["data"]
        if not isinstance(data, dict) or "id" not in data:
            raise _bad("The document record has no id.")
        attrs = data.get("attributes") or {}
        if attrs.get("restricted"):
            raise DocumentRestricted()
        parts = []
        for section in attrs.get("sections") or []:
            a = section.get("attributes", section) if isinstance(section, dict) else {}
            if a.get("resource-type") in ("Document::Heading", "Document::Text", "Document::Step"):
                parts.append(_strip_html(str(a.get("content") or "")))
        c = clean("\n".join(p for p in parts if p), budgets.max_note_chars)
        out = {"id": _int(data["id"], "document id"),
               "organization_id": _int(attrs.get("organization-id", -1), "organization id"),
               "name": cap(attrs.get("name"), MAX_ATTR_CHARS), "updated_at": attrs.get("updated-at"), "excerpt": c.text}
        if c.redacted:
            out["content_policy_applied"] = True
        if c.truncated:
            out["truncated"] = True
        return out
