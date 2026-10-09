# A support handover across ConnectWise and IT Glue

A read-only MCP server that lets Claude prepare the handover of a support ticket: the ticket and its history from
ConnectWise PSA, the configurations it concerns and an approved runbook excerpt from IT Glue. Each fact names its
source and when it was fetched, and the answer says when a source could not be consulted.

It runs as a remote connector for Claude (Streamable HTTP, OAuth). Each technician signs in as themselves, sees only
the clients the policy grants them, and PSA calls run with their own API member credentials. Password fields are
excluded by the server. Everything here runs on synthetic data: no real client, no real key, no model call.

[![ci](https://github.com/fred1433/msp-mcp-connector/actions/workflows/ci.yml/badge.svg)](https://github.com/fred1433/msp-mcp-connector/actions/workflows/ci.yml)

## A real result

The output of `get_ticket_context` for ticket 48211, taken from [`docs/demo-trace.md`](docs/demo-trace.md), which CI
regenerates on every push (shortened here; synthetic fixtures):

```json
{
  "client": { "client_ref": "CL-0142", "display_name": "Northfield Dental Group" },
  "ticket": { "id": 48211, "summary": "Front desk PCs cannot reach imaging share since this morning",
              "status": "In Progress", "priority": "Priority 2 - Quick Response",
              "source": { "system": "connectwise", "record": "service/tickets/48211", "fetched_at": "2026-10-09T14:00:00+00:00" } },
  "history": [
    { "id": 910337, "kind": "internal",
      "text": "Pinged NFD-FS01: replies. SMB from FD-01 times out. Windows Update installed KB on FD-01/02 overnight.\n[line withheld by content policy: possible credential]\nWill check firewall profile next.",
      "content_policy_applied": true },
    { "id": 910342, "kind": "internal",
      "text": "Network profile on FD-01 flipped to Public after the update; file sharing blocked. Switched FD-01 back to Domain profile as a test: share reachable. FD-02 not yet done." }
  ],
  "configurations": [
    { "id": 553201, "psa_configuration_id": 9120, "name": "NFD-FS01", "type": "Server", "primary_ip": "10.20.0.10",
      "source": { "system": "itglue", "record": "configurations/553201" } }
  ],
  "site_summary": {
    "fields": { "Internet provider": "Metro Fiber 500/500, circuit MF-88213", "Wi-Fi network": "NFD-Staff", "Firewall": ["NFD-FW01"] },
    "fields_omitted": { "password_fields": 2, "other_fields": 1 }
  },
  "sources": [ { "system": "connectwise", "status": "ok" }, { "system": "itglue", "status": "ok" } ]
}
```

## Tested, simulated, still to verify

| | |
|---|---|
| **Tested** (34 tests, every one over real HTTP through the MCP SDK) | token validation and per-request re-authorization, two technicians with two scopes, per-technician PSA credentials, ambiguous client names, out-of-scope records sent by the upstream, password fields, sessions and cursors of another user, revocation, 429, timeout, oversized response, output budget, audit content |
| **Simulated** | ConnectWise PSA and IT Glue, by per-endpoint fixtures that follow the published request and response shapes; the identity provider, by a throwaway signing key |
| **Still to verify on live systems** | the real PSA permissions of each API member, the IT Glue key's Password Access setting, the shapes marked *assumption* in [docs/api-assumptions.md](docs/api-assumptions.md), the identity provider registration, a live Claude conversation |

Three results worth reading first:

| Case | What the server returns | Test |
|---|---|---|
| A technician asks for a client they are not authorized for | `{"status": "refused", "reason": "client_not_allowed"}`, no upstream call | [`test_two_technicians_two_scopes`](tests/test_acceptance.py) |
| A technician asks for a runbook not approved for them | `{"status": "refused", "reason": "document_not_allowed"}`, the document is never fetched | [`test_restricted_document_by_policy`](tests/test_acceptance.py) |
| IT Glue returns a password field, a password tag and an unexpected `admin-password` attribute | none of the values appear in the output or the audit log; `fields_omitted.password_fields: 2` | [`test_password_fields_absent_from_output_and_audit`](tests/test_acceptance.py) |

## Illustrative scenario

This is an illustrative scenario, not a recorded Claude conversation (see [Levels of proof](#levels-of-proof)). The
tool calls and their results are real and reproduced in [`docs/demo-trace.md`](docs/demo-trace.md); the final answer
below was written for this README from those results, to show the intended shape.

> **Technician:** I'm taking over the Northfield imaging share ticket. What do I need to know?

1. `resolve_client(query="Northfield")` returns `CL-0142`, Northfield Dental Group (PSA company 250, IT Glue organization 3101).
2. `list_open_tickets(client_ref="CL-0142")` returns three open tickets, 48211 first.
3. `get_ticket_context(client_ref="CL-0142", ticket_id=48211)` returns the ticket, three notes, two configurations and the site summary.
4. `get_document_excerpt(client_ref="CL-0142", document_id=77001)` returns the approved runbook excerpt.

> **Handover, ticket 48211, Northfield Dental Group (Priority 2, in progress, owner aking)**
> - Since about 8:05, FD-01 and FD-02 get "network path not found" on S:, the imaging share. *(ConnectWise note 910331)*
> - NFD-FS01 answers ping, SMB from FD-01 times out, Windows updates were installed on FD-01/02 overnight. *(note 910337)*
> - FD-01's network profile flipped to Public after the update; setting it back to Domain restored the share. FD-02 is not done yet. *(note 910342)*
> - Server concerned: NFD-FS01, Windows Server 2022, 10.20.0.10 *(IT Glue configuration 553201)*. Firewall: NFD-FW01 *(553214)*.
> - The runbook says the same: "If S: fails after Windows updates, check the network profile is Domain, not Public." *(IT Glue document 77001)*
> - Next step: set FD-02 to the Domain profile, confirm S:, then find out why the update reset the profile.
>
> One line of note 910337 was withheld by the content policy. Both sources answered, fetched 2026-10-09 14:00 UTC.

If IT Glue had been rate limited, the same call returns `"status": "partial"` with
`{"system": "itglue", "status": "unavailable", "reason": "rate_limited"}` and the message *"Facts from those systems
are missing, not absent"*, so the answer cannot turn an outage into "no documentation".

## The four tools

All four are read-only and annotated `readOnlyHint: true`. There is no write tool.

| Tool | Does | Refuses when |
|---|---|---|
| `resolve_client(query)` | finds the client among those the technician may see, by internal reference or name | several clients match: returns `ambiguous` and the candidates, looks nothing up |
| `list_open_tickets(client_ref, cursor?)` | open PSA tickets, at most 25 per result, `has_more` and a cursor | client not granted, cursor from another user, client or query |
| `get_ticket_context(client_ref, ticket_id)` | ticket, recent notes, IT Glue configurations joined by PSA configuration ID, site summary | ticket belongs to another client |
| `get_document_excerpt(client_ref, document_id)` | an excerpt of an approved IT Glue document | document not approved for this technician, or marked restricted in IT Glue |

## Acceptance cases

Every case runs through the MCP HTTP endpoint and the adapters, against [`tests/fakes.py`](tests/fakes.py), a strict
fixture matcher: it rejects any query parameter a fixture does not list, any `conditions=` expression outside the
grammar the code generates, and any request to a password endpoint.

| Case | Test in [`tests/test_acceptance.py`](tests/test_acceptance.py) |
|---|---|
| Invalid identity (bad signature, wrong audience, wrong issuer, expired, unknown principal, no token) | `test_invalid_token_is_refused`, `test_valid_token_for_unknown_principal_is_refused`, `test_missing_token_gets_401_with_resource_metadata` |
| Two technicians, two scopes, each with their own PSA credentials | `test_two_technicians_two_scopes` |
| No PSA credential set: refusal, no shared key | `test_no_psa_credentials_means_refusal_not_shared_key` |
| Forbidden ticket ID given with an authorized client | `test_forbidden_ticket_with_authorized_client` |
| Restricted document in an authorized client | `test_restricted_document_by_policy`, `test_restricted_document_in_itglue` |
| Ambiguous client match | `test_same_display_name_is_ambiguous_and_stops` |
| Client named differently in the two systems | `test_names_differ_between_systems_but_ids_join` |
| Out-of-scope object returned by the upstream | `test_out_of_scope_records_from_upstream_are_dropped` |
| Unexpected password field, absent from output and audit | `test_password_fields_absent_from_output_and_audit`, `test_no_password_endpoint_is_ever_called`, `test_schema_unavailable_omits_all_traits` |
| Another user's session, cursor or cache | `test_session_of_another_user_is_refused`, `test_cursor_of_another_user_or_client_is_refused`, `test_no_response_cache_shared_between_users` |
| Revocation after a successful request | `test_revocation_after_a_successful_request` |
| 429 (long wait reported, short wait retried) | `test_itglue_429_is_reported_not_turned_into_no_documentation`, `test_short_429_is_retried_after_the_requested_wait` |
| Timeout | `test_timeout_is_reported` |
| Response too large; output over budget | `test_oversized_upstream_response_is_an_error_not_an_empty_answer`, `test_output_budget_truncates_with_cursor_not_silently` |
| Pagination to the end with a bound cursor | `test_pagination_with_bound_cursor_reaches_the_end` |
| Shared upstream budget across users | `test_shared_upstream_budget_is_enforced` |
| Audit record for every call, without content | `test_every_call_is_audited_without_content` |
| Tools declared read-only | `test_tools_are_declared_read_only` |

## Levels of proof

1. **Automated tests on fixtures**: done, 34 tests, green in CI on Python 3.12 and 3.13. CI also regenerates the demo
   trace and fails if it changed.
2. **A live Claude conversation** through a public tunnel against the fixtures: not done yet. That is why the
   scenario above is labelled illustrative and the real MCP exchange is published separately in
   [`docs/demo-trace.md`](docs/demo-trace.md).
3. **A pilot on the MSP's own systems**: not done.

## How it is built

```
Claude (Team / Enterprise custom connector)
   |  Streamable HTTP + OAuth bearer token (issued by the MSP's identity provider)
   v
MCP server (official Python SDK)  ->  token check (iss, aud, exp, signature) + policy check, every request
   |
   +-- policy.json        principal -> clients, documents ; client_ref -> PSA company id -> IT Glue org id
   +-- PSA credentials    principal -> that technician's API member keys (no shared fallback)
   +-- ConnectWise adapter   allowlisted fields, company check on every record
   +-- IT Glue adapter       allowlisted fields, field-kind filter, no password endpoint
   +-- audit log             ids and decisions only
```

Details: [authorization model](docs/authorization.md), [API facts and assumptions](docs/api-assumptions.md),
[connecting to Claude](docs/claude-admin.md).

## Existing components considered

Read on 2026-10-09 at the commits shown.

| Repository | What it offers | Use here |
|---|---|---|
| [WYRE-AI/connectwise-manage-mcp](https://github.com/WYRE-AI/connectwise-manage-mcp) @ `86ba595` | TypeScript, stdio and Streamable HTTP, optional Entra ID OAuth for inbound access, an Azure Container Apps deployment guide; PSA keys from the environment, or per request from their gateway | Its Entra and Container Apps notes are a good deployment reference. The handover needs per-technician PSA keys selected from the token, so a small adapter is written instead |
| [WYRE-AI/itglue-mcp](https://github.com/WYRE-AI/itglue-mcp) @ `feec047` | Broad IT Glue coverage, including password tools (`get_password`) | Not reused: this repository's scope excludes every password path, which is simpler to audit in a narrow adapter |
| [WYRE-AI/msp-claude-plugins](https://github.com/WYRE-AI/msp-claude-plugins) @ `a94788d` | Claude plugins pointing at hosted servers; governance described through their gateway, whose source is not public | Not reused |
| [mspstack/mcp-connectwise-psa](https://github.com/mspstack/mcp-connectwise-psa) @ `35638a8` | Per-user keys on each HTTP session, session bound to the key pair; the PSA member's security role is the access control | Closest to the PSA model here. A production build could adopt it behind the same policy and output allowlists |
| [mspstack/mcp-itglue](https://github.com/mspstack/mcp-itglue) @ `05304bf` | No password tools; the generic GET passthrough blocks `/passwords`; role tokens | Same stance on passwords. Not reused because the handover needs per-client document approval and field-kind filtering |
| [mspstack/mcp-gateway](https://github.com/mspstack/mcp-gateway) @ `d16ca5e` | OAuth 2.1 resource server, per-user upstream credentials in a key vault, every `tools/call` logged | Worth evaluating as the front door in production |
| [bradleiby/cld-cwm-mcp](https://github.com/bradleiby/cld-cwm-mcp) @ `159fdb6` | Python, Streamable HTTP, one shared API key, writes behind a flag, Bicep for Container Apps | Not reused: one shared key does not give per-technician scope |

## Deferred

- **Writes** (ticket notes, time entries). A write will require an authenticated human approval, outside the model's reach.
- Enterprise Managed Auth (option to evaluate, see [docs/claude-admin.md](docs/claude-admin.md)), a search index,
  an administration screen, and the other integrations below.

## Extension plan: dependencies to lift

Other tools join as adapters behind the same identity, policy, allowlist and audit layers. What decides the order:

1. **Which RMM** is in use, and whether its API exposes device state per client.
2. **RMM or Auvik first**, depending on which flow the technicians need most in a handover: device state or network topology.
3. **Which Dynamics and which Sage products** exactly (each name covers several products with different APIs).
4. **The role of Pia and CloudRadial** in the service desk flow (automation, client portal), which decides read or write needs.
5. **"Client Success"**: unresolved; which system this refers to needs confirming.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -v                       # 34 acceptance tests, fixtures only
python scripts/demo_trace.py    # regenerates docs/demo-trace.md
```

Against live systems (read-only), the server reads its settings from the environment:

| Variable | Meaning |
|---|---|
| `HANDOVER_RESOURCE_URL` | public URL of `/mcp`, exactly as entered in Claude |
| `HANDOVER_ISSUER`, `HANDOVER_AUDIENCE`, `HANDOVER_JWKS_URL` | the identity provider's issuer, this API's audience, its JWKS |
| `HANDOVER_POLICY_FILE`, `HANDOVER_PSA_CREDENTIALS_FILE` | policy and per-technician PSA credentials (see `config/*.example.json`) |
| `HANDOVER_CW_BASE_URL`, `HANDOVER_CW_CLIENT_ID` | ConnectWise API base URL and client ID |
| `HANDOVER_ITGLUE_API_KEY`, `HANDOVER_ITGLUE_REGION` | IT Glue key (Password Access off) and region `us`, `eu` or `au` |
| `HANDOVER_CURSOR_SECRET`, `HANDOVER_AUDIT_FILE` | cursor signing secret, audit log path |

```bash
support-handover   # serves /mcp on $PORT (default 8000)
```

MIT licensed. Built by [The AI Pipe](https://theaipipe.com).
