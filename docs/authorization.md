# Authorization model

Short version: a validated token names a principal; a policy file says what that principal may see; ConnectWise
calls run with that technician's own API member credentials; IT Glue output is built from allowlists; every call
is audited without content. The sample enforces its stated policy. Whether that policy matches the real
permissions of each technician is an acceptance task (end of this page).

## 1. Who is calling

- The principal is the pair `(iss, sub)` of an access token whose signature, issuer, audience and expiry are valid
  (`src/handover/identity.py`). An e-mail claim, a display name or a tool argument never grants anything.
- The check runs on every HTTP request, not once per session. A principal that is unknown, disabled, or covered by
  the global `kill_switch` receives `401`.
- MCP sessions are bound to the principal by the SDK: another user presenting someone else's `Mcp-Session-Id` is
  refused (`test_session_of_another_user_is_refused`).

## 2. ConnectWise PSA: each principal has its own credentials

- `psa_credential` in the policy points to that technician's API member key set (`config/psa-credentials.example.json`
  in the demo; a secret store in production). Requests run with that member's credentials; effective PSA
  permissions require live verification.
- No credential set for a principal means a refusal (`no_psa_credentials`). There is no shared fallback key.
- The connector also checks, on every record, that the PSA company is the one mapped to the requested client.
  A ticket number that belongs to another client is refused even if the member can read it
  (`test_forbidden_ticket_with_authorized_client`).

## 3. IT Glue: an explicit policy

IT Glue's `GET /users/:id` accepts `check_authorization`, described in the reference as a "Comma-separated list of
resource types to check authorization for (e.g., 'Document,Password,Configuration')"
([API reference](https://api.itglue.com/developer/)). It answers per resource type, not per organization or per
document, so it cannot prove that a technician may read a given client's document. It is not used as evidence.

Instead the policy lists, per principal, the clients (and so the IT Glue organizations) and the document IDs that
principal may read. A document not listed is refused before any request is made
(`test_restricted_document_by_policy`). A document IT Glue marks `restricted` is refused whatever the policy says
(`test_restricted_document_in_itglue`).

## 4. One client across two systems

`client_ref` (internal reference) -> PSA company ID -> IT Glue organization ID, declared in the policy. Two clients
are never joined by name. The MSP's own PSA login company (`company_id` in the credentials) is distinct from any
client's company ID. If a name matches several clients, `resolve_client` returns `ambiguous` and nothing is
looked up until one `client_ref` is chosen (`test_same_display_name_is_ambiguous_and_stops`). Configurations are
joined by PSA configuration ID through IT Glue's `filter[psa_id]` with `filter[psa_integration_type]=manage`.

## 5. Password fields and secrets in text

1. No code path calls a password endpoint or requests password relationships (`test_no_password_endpoint_is_ever_called`).
2. Outputs are built field by field from allowlists; an unexpected attribute such as `admin-password` on a
   configuration is dropped (`test_password_fields_absent_from_output_and_audit`).
3. Flexible asset traits are kept only when the field definition says they are a safe kind. `Password` fields and
   `Tag` fields whose `tag-type` is `Passwords` are excluded; traits absent from the definitions are dropped; if the
   definitions cannot be loaded, every trait is omitted (`test_schema_unavailable_omits_all_traits`).
4. A field whose **name** suggests a secret (contains pass, pwd, PIN, PSK, key, secret, credential, creds, token,
   MFA, OTP or code) is omitted whatever its kind, because home-made templates often keep secrets in Text fields
   (`test_a2_site_summary_secret_named_text_field_and_big_text`, `test_secret_sounding_field_names`). This errs on
   the side of omission: a field named "Postal code" is omitted too.
5. Deployment setting: IT Glue documents "an optional Password Access setting ... for each API key" and "Password
   values can be accessed from the Passwords API only if this setting is enabled"
   ([Getting started with the IT Glue API](https://help.itglue.kaseya.com/help/Content/1-admin/it-glue-api/getting-started-with-the-it-glue-api.html)).
   Generate the key with that setting off. Fixtures cannot prove how a real key is configured; this stays an
   acceptance task.

Free text and text fields (ticket summaries and notes, document sections, Text and Textbox traits) cannot be
allowlisted field by field. They pass through a separate content policy (`src/handover/content.py`) that withholds:

- any line containing a secret word (password, passcode, pass, pwd, pw, PIN, PSK, key, secret, token, credential,
  creds, MFA, OTP, backup / recovery / door code, "mot de passe"), whatever the separator (`:`, `=`, `-`, `is`,
  `set to`, a space);
- the next non-empty line when such a line ends with a label and no value (`Password:` then the value below);
- command lines carrying a password (`net user NAME VALUE`, `sshpass`, `-p VALUE`, `admin ... / VALUE`);
- PEM private keys, terminated or not.

Each form has its own test in `tests/test_content_policy.py`. The policy prefers withholding: a harmless line such
as "Key contact: Dr Lee" is withheld too. Its limit: a secret written with none of these words or shapes
("the usual one is Hunter2") is not detected. That is why the demo uses synthetic, approved excerpts only, and why
the IT Glue key should have Password Access off.

Every text value is also capped (600 characters for notes and text fields, 300 for names), and a cut is flagged
(`truncated`, `truncated_fields`).

## 6. Audit

One JSON line per tool call, including calls that fail: principal, client reference, tool, source record IDs,
decision (`allowed`, `partial`, `refused`, `failed`, `error`), reason code, policy version, timestamp, correlation
ID. Never: record content, note text, credentials, tokens, upstream bodies or upstream exception messages; an
unexpected error is recorded as `internal_error:<exception class>` only (`test_every_call_is_audited_without_content`,
`test_a3_unexpected_internal_error_is_audited`). If the audit line cannot be written, the call returns no data
(`test_a3_unwritable_audit_log_returns_no_data`).

## 7. Revocation and disabling

| Situation | Action | Effect |
|---|---|---|
| One technician leaves or a token is suspected stolen | Add `"<iss>|<sub>"` to `disabled_principals` in the policy file | `401` at that principal's next request, open sessions included |
| Narrow a technician's scope | Edit `clients` / `documents`, bump `version` | Next call uses the new scope; audit lines carry the new version |
| A PSA key is exposed | Delete that API member's key in ConnectWise, remove it from the credential store | That principal is refused (`no_psa_credentials`) |
| The IT Glue key is exposed | Revoke it in IT Glue, deploy a new one without Password Access | IT Glue calls fail cleanly (`upstream_http_401`) until replaced |
| Stop everything | Set `"kill_switch": true` | Every request gets `401` |
| Revoke Claude's access for everyone | Remove the connector in Organization settings > Connectors, and revoke the client at the identity provider | Members can no longer connect |

The policy file is re-read when its modification time changes; no restart is needed.

## Acceptance tasks (to do with live systems)

- Map each technician's `sub` to their PSA API member and confirm, member by member, which companies and tickets the
  PSA security role really allows.
- Confirm the IT Glue policy (clients, documents) matches what each technician may see in IT Glue.
- Confirm the IT Glue API key has Password Access off.
- Replay the acceptance tests against a sandbox or a read-only pilot and record any shape difference from the fixtures.
