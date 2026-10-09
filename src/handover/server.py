"""MCP server: Streamable HTTP, OAuth resource server, four read-only tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import httpx
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from .audit import AuditLog
from .config import Settings
from .connectwise import ConnectWise
from .credentials import CredentialStore
from .cursor import CursorCodec
from .identity import JwtVerifier, current_principal
from .itglue import ITGlue
from .policy import Policy
from .tools import Handover
from .upstream import SharedBudget

INSTRUCTIONS = (
    "Read-only support handover across ConnectWise PSA and IT Glue. "
    "Start with resolve_client; if it says 'ambiguous', ask the technician which client_ref is meant. "
    "Every fact carries a source (system, record, fetched_at): cite it. "
    "If a source is reported unavailable, say that its facts are missing, never that they do not exist. "
    "Password fields are excluded by the server and cannot be requested."
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


@dataclass
class App:
    mcp: MCPServer
    handover: Handover
    policy: Policy
    audit: AuditLog

    def asgi(self):
        return self.mcp.streamable_http_app(json_response=True, host="0.0.0.0")


def build(settings: Settings, *, upstream_transport: httpx.AsyncBaseTransport | None = None,
          jwks: dict | None = None, audit: AuditLog | None = None, sleep=None, clock_iso=None) -> App:
    policy = Policy(settings.policy_file)
    audit = audit or AuditLog(settings.audit_file)
    verifier = JwtVerifier(
        issuer=settings.issuer, audience=settings.audience, resource_url=settings.resource_url,
        jwks_url=None if jwks else settings.jwks_url,
        jwks=jwks or (JwtVerifier.jwks_from_file(settings.jwks_file) if settings.jwks_file else None),
        is_authorized=policy.is_active,
    )
    http = httpx.AsyncClient(transport=upstream_transport) if upstream_transport else httpx.AsyncClient()
    b = settings.budgets
    kwargs = {"sleep": sleep} if sleep else {}
    cw = ConnectWise(settings.connectwise_base_url, settings.connectwise_client_id, http,
                     SharedBudget(b.connectwise_requests_per_window, b.window_s), b, **kwargs)
    itg = ITGlue(settings.itglue_base_url, settings.itglue_api_key, http,
                 SharedBudget(b.itglue_requests_per_window, b.window_s), b,
                 site_summary_type_id=settings.itglue_site_summary_type_id, **kwargs)
    handover = Handover(policy=policy, credentials=CredentialStore(settings.credentials_file), connectwise=cw,
                        itglue=itg, cursors=CursorCodec(settings.cursor_secret), audit=audit, budgets=b)
    if clock_iso:
        handover.clock_iso = clock_iso

    mcp = MCPServer(
        "support-handover",
        title="Support handover (ConnectWise PSA + IT Glue)",
        instructions=INSTRUCTIONS,
        version="0.1.0",
        token_verifier=verifier,
        auth=AuthSettings(issuer_url=settings.issuer, resource_server_url=settings.resource_url,
                          validate_token_resource=False),  # audience is checked by JwtVerifier
    )

    @mcp.tool(title="Resolve client", annotations=READ_ONLY)
    async def resolve_client(
        query: Annotated[str, Field(description="Client name or internal client reference, e.g. 'CL-0142'.")],
    ) -> dict:
        """Find the client the technician means, among the clients they are authorized for.
        Returns client_ref values to use with the other tools. Never guesses between clients that share a name."""
        return await handover.resolve_client(current_principal(), query)

    @mcp.tool(title="List open tickets", annotations=READ_ONLY)
    async def list_open_tickets(
        client_ref: Annotated[str, Field(description="client_ref from resolve_client.")],
        cursor: Annotated[str | None, Field(description="Cursor from a previous call, to continue the list.")] = None,
    ) -> dict:
        """Open ConnectWise PSA tickets for one client. Paginated: when has_more is true, call again with cursor."""
        return await handover.list_open_tickets(current_principal(), client_ref, cursor)

    @mcp.tool(title="Get ticket context", annotations=READ_ONLY)
    async def get_ticket_context(
        client_ref: Annotated[str, Field(description="client_ref from resolve_client.")],
        ticket_id: Annotated[int, Field(description="ConnectWise PSA ticket number.")],
    ) -> dict:
        """Everything needed to hand over one ticket: the ticket, its recent history, the IT Glue
        configurations attached to it, and the client's site summary. Each fact names its source."""
        return await handover.get_ticket_context(current_principal(), client_ref, ticket_id)

    @mcp.tool(title="Get document excerpt", annotations=READ_ONLY)
    async def get_document_excerpt(
        client_ref: Annotated[str, Field(description="client_ref from resolve_client.")],
        document_id: Annotated[int, Field(description="IT Glue document id.")],
    ) -> dict:
        """An approved excerpt of one IT Glue document, if the policy approves it for this technician."""
        return await handover.get_document_excerpt(current_principal(), client_ref, document_id)

    return App(mcp=mcp, handover=handover, policy=policy, audit=audit)


def main() -> None:  # pragma: no cover
    import os

    import uvicorn

    app = build(Settings.from_env())
    uvicorn.run(app.asgi(), host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")))


if __name__ == "__main__":  # pragma: no cover
    main()
