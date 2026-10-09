# Connecting the server to Claude (Team / Enterprise)

Every statement about Claude below was read in Anthropic's documentation on 2026-10-09 and links to its page.
Where this repository makes its own choice, it says so.

## What Claude expects from a remote MCP server

| Topic | What the documentation says | Source |
|---|---|---|
| Transport | "Use Streamable HTTP, which the MCP specification defines for remote servers. Claude also supports the legacy HTTP+SSE transport, which is being deprecated in favor of Streamable HTTP." | [Building connectors](https://claude.com/docs/connectors/building) |
| Reachability | "Claude reaches your server from Anthropic's infrastructure, so a server running on your machine needs a public URL." | [Testing](https://claude.com/docs/connectors/building/testing) |
| Private network option | "MCP tunnels are in research preview and are available to organizations on the Claude Enterprise plan by request." A tunnel stack inside the network "opens an outbound-only connection to Anthropic"; "Your firewall needs no inbound rules and your MCP servers need no public endpoint." Each server behind a tunnel still needs its own OAuth. | [MCP tunnels](https://claude.com/docs/connectors/mcp-tunnels/overview) |
| Egress IPs | "Anthropic's outbound traffic to your server originates from `160.79.104.0/21`." | [Authentication](https://claude.com/docs/connectors/building/authentication), [IP addresses](https://platform.claude.com/docs/en/api/ip-addresses) |
| Identity provider reachability | The authorization server "must also be reachable from Anthropic's published egress range", and a WAF in front of the identity provider can break the flow. | [Authentication](https://claude.com/docs/connectors/building/authentication) |
| OAuth is optional | Three modes are listed: OAuth 2.0, a static credential, or no authentication. | [Authentication](https://claude.com/docs/connectors/building/authentication) |
| Callback URL | "register exactly this redirect URI: `https://claude.ai/api/mcp/auth_callback`" | [Authentication](https://claude.com/docs/connectors/building/authentication) |
| PKCE | "Claude includes a PKCE `code_challenge` with `code_challenge_method=S256` on every authorization request... Your authorization server must support S256 PKCE." | [Authentication](https://claude.com/docs/connectors/building/authentication) |
| 401 challenge | "Return `401` with a `resource_metadata` pointer". The `resource` value "must equal the URL as the user enters it in Claude, including any path component." | [Authentication](https://claude.com/docs/connectors/building/authentication) |
| Client registration | Claude's published client identity (CIMD), Dynamic Client Registration, or "an OAuth client ID the customer registered with you and enters in the dialog". | [Authentication](https://claude.com/docs/connectors/building/authentication), [Add a custom connector](https://claude.com/docs/connectors/custom/add-unlisted) |
| Static request headers | Listed as "Beta, for a limited set of organizations"; on an OAuth connection "you can't configure `Authorization` as a request header". | [Authentication](https://claude.com/docs/connectors/building/authentication), [Add a custom connector](https://claude.com/docs/connectors/custom/add-unlisted) |
| Tool result size | "Maximum tool result size: ~150,000 characters" on claude.ai and Desktop. | [Building connectors](https://claude.com/docs/connectors/building) |
| Tool call time | "240 seconds per tool call" on claude.ai and Desktop. | [Building connectors](https://claude.com/docs/connectors/building) |
| Research mode | "During the research process, Claude can invoke tools from your connectors automatically without further approval." | [Custom connectors (support)](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) |
| Auth spec versions | "Claude follows the 2025-03-26, 2025-06-18, and 2025-11-25 authorization specifications". | [Building connectors](https://claude.com/docs/connectors/building) |

## How this server meets it

- **Transport**: Streamable HTTP at `/mcp`, from the official MCP Python SDK (`mcp==2.3.0`).
- **OAuth**: chosen here, although Claude does not require it, because it is the only mode that gives a per-user identity. The server is an OAuth *resource server* only. Tokens are issued by the MSP's existing identity provider; the server validates signature, `iss`, `aud` and `exp` with PyJWT against the provider's JWKS, and answers `401` with a `resource_metadata` pointer (tested: `test_missing_token_gets_401_with_resource_metadata`). No identity provider is written here.
- **Audience**: `HANDOVER_AUDIENCE` must equal what the identity provider puts in `aud` for this API, and `HANDOVER_RESOURCE_URL` must equal the URL the Owner types in Claude.
- **Every HTTP request is re-authorized**: the token is checked, then the principal is looked up in the policy. A disabled principal gets `401` at its next request, inside an open session (tested: `test_revocation_after_a_successful_request`).
- **Size and time budgets**: every tool result is capped at 24,000 characters, measured on the exact text the MCP SDK sends (`pydantic_core.to_json(..., indent=2)`), with a `truncated` flag when something was cut; each tool call has a 20-second deadline for its upstream HTTP calls, and text processing is bounded by input size. Both stay well under the limits above (Claude's ~150,000 characters and 240 seconds, re-read on 2026-10-09). These are this repository's choices (`test_a3_200k_text_field_stays_under_the_output_budget`, `test_v8_budget_is_measured_on_the_text_mcp_sends`).
- **Research mode**: because tools can be called without per-call approval there, the server exposes no write tool at all. Any future write needs an authenticated human approval that the model cannot produce (see README, Deferred).
- **Not on the internet?** If the MSP will not expose this server publicly, MCP tunnels (Enterprise, research
  preview, on request) are the documented route. This server already speaks Streamable HTTP and requires OAuth, which
  is what a tunnelled server needs. Not tested here.
- **IP allowlist**: restricting inbound traffic to `160.79.104.0/21` (plus the identity provider path) is a reasonable network layer. This repository treats it as a complement to token validation, never a replacement. That position is ours; the documentation does not state it either way.

## Administrator steps

From [Add a custom connector](https://claude.com/docs/connectors/custom/add-unlisted):

1. An Owner goes to **Organization settings > Connectors** ([link](https://claude.ai/admin-settings/connectors)).
2. **Add**, then **Custom**. If Claude asks for the connector type, choose **Web**.
3. Enter the server URL (for example `https://handover.example-msp.com/mcp`). Under the OAuth options, either use Claude's published identity, or enter the client ID (and secret, if the client is confidential) registered for Claude at the identity provider. Click **Add**.
4. Members then go to **Customize > Connectors**, find the connector with the **Custom** label, and click **Connect** to sign in with their own account.

Two notes from the same page: "On Team and Enterprise plans, an Owner adds the connector for the organization, and members then connect with their own account", and "You can't change authentication settings after you add a connector... remove the connector and add it again... Members then need to reconnect."

## Identity provider checklist (acceptance tasks, not done here)

- Register an application for this API; its identifier is the `aud` the server expects.
- Register `https://claude.ai/api/mcp/auth_callback` as the redirect URI of the client Claude uses.
- With Microsoft Entra ID, Anthropic writes: "you must also register the MCP server URL as an Application ID URI on
  your Entra app registration, or the token request fails with `AADSTS9010010`. By default, Entra accepts that URL
  as an Application ID URI only when it's on a domain your tenant has verified"
  ([Authentication](https://claude.com/docs/connectors/building/authentication)). Microsoft's page shows the
  condition depends on the token format and the tenant policy: `https://` identifier URIs follow the secure patterns
  on a verified custom domain or the tenant's initial `onmicrosoft.com` domain; the policy that enforces them can be
  enabled, disabled or given exemptions by a tenant administrator; apps set to v2.0 tokens
  (`api.requestedAccessTokenVersion` = 2) are exempted by default; and "even when the setting is disabled, a tenant
  verified or initial domain may still be required in some scenarios - for example, when using the `https://`
  scheme" ([Restrictions on identifier URIs](https://learn.microsoft.com/en-us/entra/identity-platform/identifier-uri-restrictions)).
  Plan for a custom domain on the server unless the identity administrator confirms otherwise.
- With v2.0 Entra tokens, `aud` "is always the client ID of the API", so `HANDOVER_AUDIENCE` is that client ID
  ([Access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)).
- Scopes, to do with the identity administrator: expose one delegated scope for this API (for example
  `handover.read`), grant consent for it, have the server check `scp` (Microsoft: "The application should verify
  that these scopes are valid ones exposed by the application", same page), and advertise the scope in the `401`
  challenge and in `scopes_supported` of the protected resource metadata. Anthropic: "To control which scopes Claude
  requests, include a `scope` parameter in the `WWW-Authenticate` header on your `401` response. If you don't,
  Claude requests the scopes your protected resource metadata advertises in `scopes_supported`." Not implemented in
  this repository; it belongs to the pilot.
- Confirm the provider supports PKCE S256 and is reachable from `160.79.104.0/21`.
- Decide how a token's `sub` maps to a technician (policy file today; a directory group sync later).

## Option to evaluate: Enterprise Managed Auth

"Enterprise Managed Auth (EMA) lets a user connect to your MCP server silently, using the single sign-on session they already have with their organization." It requires a Team or Enterprise plan and an authorization server that supports the RFC 7523 jwt-bearer grant, and "Dynamic Client Registration (DCR) isn't supported with Enterprise Managed Auth." ([Enterprise Managed Auth](https://claude.com/docs/connectors/building/enterprise-managed-auth)). Not implemented here; worth evaluating with the identity administrator.
