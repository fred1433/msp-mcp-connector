# API facts and assumptions

Each fixture in `fixtures/` carries a `provenance` block with one of these statuses:

- **verified**: read in the vendor's public documentation (link below).
- **third-party**: taken from a public implementation or integration doc, not from the vendor. Linked.
- **assumption**: not found in any public source; chosen to be the most conservative reading.
- **hostile**: deliberate misbehaviour the connector must survive (out-of-scope records, unknown fields, oversized bodies).

Read on 2026-10-09.

## IT Glue

| Fact used by the code | Status | Source |
|---|---|---|
| Headers `x-api-key` and `Content-Type: application/vnd.api+json` | verified | [API reference](https://api.itglue.com/developer/) |
| Regional hosts `api.itglue.com`, `api.eu.itglue.com`, `api.au.itglue.com` (setting `HANDOVER_ITGLUE_REGION`) | verified | [API reference](https://api.itglue.com/developer/) |
| "a maximum of 3000 requests within a 5-minute window"; "A 429 Too Many Requests error code will be returned" | verified | [API reference](https://api.itglue.com/developer/) |
| `Retry-After` on a 429 | **assumption** (not documented). The connector reads it as seconds or as an HTTP date (RFC 9110) if present; otherwise it uses a bounded backoff and says the wait was its own | n/a |
| Pagination `page[number]` / `page[size]` (max 1000, default 50). The adapter pages through field definitions (`page[size]=100`, up to 5 pages, then reports `field_definitions_incomplete` and omits every trait). Configuration and site summary lookups read one page: a `meta.next-page` there is reported (`configurations_has_more`, or an ambiguous site summary), never ignored | verified (parameters); `meta.next-page` shape: third-party, [b-loyola/itglue README](https://github.com/b-loyola/itglue) | [API reference](https://api.itglue.com/developer/), [Pagination help](https://help.itglue.kaseya.com/help/Content/1-admin/it-glue-api/pagination-in-the-it-glue-api.html) |
| `GET /organizations/:id` | verified | [API reference](https://api.itglue.com/developer/) |
| `GET /configurations` with `filter[organization_id]`, `filter[psa_id]` + `filter[psa_integration_type]` (values include `manage`) | verified (filters listed in the Configurations section; "must be accompanied by the filter for psa_integration_type") | [API reference](https://api.itglue.com/developer/) |
| Configuration attributes used: `name`, `hostname`, `configuration-type-name`, `configuration-status-name`, `serial-number`, `primary-ip`, `operating-system-name`, `organization-id`, `updated-at` | verified (example response) | [API reference](https://api.itglue.com/developer/) |
| `GET /flexible_assets` with `filter[flexible-asset-type-id]` (required) and `filter[organization-id]`, written with hyphens. The type comes from `HANDOVER_ITGLUE_SITE_SUMMARY_TYPE_ID`; more than one result for an organization is reported as ambiguous, never resolved by taking the first | verified | [API reference](https://api.itglue.com/developer/) |
| Field definitions at `GET /flexible_asset_types/:id/relationships/flexible_asset_fields`, with `kind`, `tag-type`, `name-key`; kinds include `Password` and `Tag`; tag types include `Passwords` | verified | [API reference](https://api.itglue.com/developer/) |
| Traits keyed by `name-key`; tag traits as `{"type": ..., "values": [...]}` | verified (example) | [API reference](https://api.itglue.com/developer/) |
| How a `Password` field's value appears inside traits | **assumption** (a plain value). The connector does not depend on it: it excludes by field kind | n/a |
| `GET /organizations/:org_id/relationships/documents/:id` "including its sections"; attribute `restricted` | verified | [API reference](https://api.itglue.com/developer/) |
| Section attributes `resource-type` (`Document::Text`, `Document::Heading`, ...) and `content` | verified (example) | [API reference](https://api.itglue.com/developer/) |
| Exact nesting of each section object inside `sections` | **assumption**; the adapter accepts flat or JSON:API-nested objects | n/a |
| API keys have an optional Password Access setting | verified | [Getting started](https://help.itglue.kaseya.com/help/Content/1-admin/it-glue-api/getting-started-with-the-it-glue-api.html) |

## ConnectWise PSA

The vendor's developer reference requires a login, so nothing below is presented as the vendor's specification.
Every item is issued from a third-party implementation or integration doc, linked. No step of the plan depends on
obtaining a developer account or a sandbox; the live check is an acceptance task.

| Fact used by the code | Status | Source |
|---|---|---|
| Basic auth `companyId+publicKey:privateKey` | third-party | [ConnectWiseManageAPI, Connect-CWM.ps1 line 50](https://github.com/christaylorcodes/ConnectWiseManageAPI/blob/e7f08423c31a632b894f1b6c33de653c642b5274/ConnectWiseManageAPI/Public/Authentication/Connect-CWM.ps1#L50): `"$($Company)+$($PubKey):$($PrivateKey)"`; [Nango](https://www.nango.dev/docs/api-integrations/connectwise-psa/connect.md) describes the same in words |
| `clientId` header required | third-party | [ConnectWiseManageAPI](https://github.com/christaylorcodes/ConnectWiseManageAPI) ("As of 8/14/2019 ConnectWise requires the use of a Client ID"), [ConnectPyse README](https://github.com/markciecior/ConnectPyse) |
| Host `api-na.myconnectwise.net` (also `api-eu`, `api-au`) and path `/v4_6_release/apis/3.0` | third-party | [Nango](https://www.nango.dev/docs/api-integrations/connectwise-psa/connect.md), [ConnectPyse README](https://github.com/markciecior/ConnectPyse) |
| Query parameters `conditions`, `orderBy`, `page`, `pageSize` (max 1000) | third-party | [ConnectPyse cw_controller.py](https://github.com/markciecior/ConnectPyse/blob/master/connectpyse/cw_controller.py), [pyconnectwise README](https://github.com/HealthITAU/pyconnectwise) |
| `conditions` syntax `company/id=250 and closedFlag=false` | third-party | [pyconnectwise README](https://github.com/HealthITAU/pyconnectwise) (`company/id=250`), [ConnectPyse ticket.py](https://github.com/markciecior/ConnectPyse/blob/master/connectpyse/service/ticket.py) (`closedFlag`) |
| Ticket fields `id`, `summary`, `board`, `status`, `company`, `priority`, `_info`, `closedFlag` | third-party | [ConnectPyse ticket.py](https://github.com/markciecior/ConnectPyse/blob/master/connectpyse/service/ticket.py) |
| `_info.dateEntered`, `_info.lastUpdated` | **assumption** (field names inside `_info` not confirmed) | n/a |
| Note fields `text`, `detailDescriptionFlag`, `internalAnalysisFlag`, `resolutionFlag`, `dateCreated`, `createdBy` | third-party | [ConnectPyse ticket_note.py](https://github.com/markciecior/ConnectPyse/blob/master/connectpyse/service/ticket_note.py) |
| `GET /service/tickets/{id}/configurations` returns `{id, deviceIdentifier}` items | **assumption** (third-party source shows this shape for the payload only) | [ConnectPyse tickets_api.py](https://github.com/markciecior/ConnectPyse/blob/master/connectpyse/service/tickets_api.py) |
| Next page signalled by a `Link` header with `rel="next"` | **assumption**, weakly sourced; the connector also treats a full page as "maybe more", so a missing header costs one extra request, never a missed page | n/a |
| Rate limits | not found in any reliable public source. The connector keeps its own shared budget (`connectwise_requests_per_window`) and handles 429 like IT Glue | n/a |

## Budgets (this repository's choices)

| Budget | Value | Vendor limit it stays under |
|---|---|---|
| Records per result (tickets, configurations) | 25, then `has_more` | n/a |
| Text per note or text field | 600 characters, cut flagged | n/a |
| Output per result (any tool, whole result) | 24,000 characters, cut flagged with `truncated` | Claude: ~150,000 characters per tool result |
| Time per tool call | 20 s | Claude: 240 s per tool call |
| Upstream pages per call | 4 | n/a |
| Upstream timeout | 8 s per request | n/a |
| Largest accepted upstream body | 2 MB | IT Glue help mentions a 10 MB payload limit |
| IT Glue requests, shared by all users | 2,400 per 5 min | IT Glue: 3,000 per 5 min |
| ConnectWise requests, shared by all users | 1,000 per 5 min | unknown (see above) |
| Retries | 2, and only if the requested wait is at most 10 s and fits the call's deadline | n/a |
