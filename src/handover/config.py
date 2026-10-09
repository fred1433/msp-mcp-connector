"""Runtime settings and the application budgets.

Every number in `Budgets` is a choice made in this repository, not a vendor limit.
The vendor limits they stay under are cited in docs/api-assumptions.md.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# IT Glue regional API hosts. Source: see docs/api-assumptions.md (IT Glue section).
ITGLUE_REGIONS = {
    "us": "https://api.itglue.com",
    "eu": "https://api.eu.itglue.com",
    "au": "https://api.au.itglue.com",
}


@dataclass(frozen=True)
class Budgets:
    # Claude accepts tool results up to about 150,000 characters (claude.ai / Desktop).
    # We stay far below it so a handover stays readable and cheap in context.
    max_records: int = 25
    max_output_chars: int = 24_000
    # Upstream work per tool call.
    max_upstream_pages: int = 4
    upstream_timeout_s: float = 8.0
    max_upstream_bytes: int = 2_000_000
    # Claude allows 240 s per tool call; we answer (possibly partially) well before.
    tool_deadline_s: float = 20.0
    max_retries: int = 2
    max_retry_wait_s: float = 10.0
    # Shared across all users of this server, per upstream system.
    # IT Glue publishes 3,000 requests per 5 minutes; we keep 20% headroom.
    itglue_requests_per_window: int = 2_400
    connectwise_requests_per_window: int = 1_000
    window_s: float = 300.0
    # Free text (ticket notes) is cut to this length after the content policy runs.
    max_note_chars: int = 600
    max_notes: int = 8


@dataclass(frozen=True)
class Settings:
    resource_url: str
    issuer: str
    audience: str
    jwks_url: str | None
    jwks_file: Path | None
    policy_file: Path
    credentials_file: Path
    audit_file: Path | None
    cursor_secret: bytes
    itglue_region: str = "us"
    itglue_api_key: str = ""
    connectwise_base_url: str = "https://api-na.myconnectwise.net/v4_6_release/apis/3.0"
    connectwise_client_id: str = ""
    # IT Glue flexible asset type used as the client's site summary; None disables that part.
    itglue_site_summary_type_id: int | None = None
    budgets: Budgets = field(default_factory=Budgets)

    @property
    def itglue_base_url(self) -> str:
        try:
            return ITGLUE_REGIONS[self.itglue_region]
        except KeyError as exc:
            raise ValueError(f"unknown IT Glue region {self.itglue_region!r}, expected one of {sorted(ITGLUE_REGIONS)}") from exc

    @classmethod
    def from_env(cls) -> "Settings":
        def req(name: str) -> str:
            value = os.environ.get(name)
            if not value:
                raise RuntimeError(f"missing required environment variable {name}")
            return value

        jwks_file = os.environ.get("HANDOVER_JWKS_FILE")
        audit = os.environ.get("HANDOVER_AUDIT_FILE")
        return cls(
            resource_url=req("HANDOVER_RESOURCE_URL"),
            issuer=req("HANDOVER_ISSUER"),
            audience=os.environ.get("HANDOVER_AUDIENCE") or req("HANDOVER_RESOURCE_URL"),
            jwks_url=os.environ.get("HANDOVER_JWKS_URL"),
            jwks_file=Path(jwks_file) if jwks_file else None,
            policy_file=Path(req("HANDOVER_POLICY_FILE")),
            credentials_file=Path(req("HANDOVER_PSA_CREDENTIALS_FILE")),
            audit_file=Path(audit) if audit else None,
            cursor_secret=req("HANDOVER_CURSOR_SECRET").encode(),
            itglue_region=os.environ.get("HANDOVER_ITGLUE_REGION", "us"),
            itglue_api_key=req("HANDOVER_ITGLUE_API_KEY"),
            connectwise_base_url=os.environ.get("HANDOVER_CW_BASE_URL", cls.connectwise_base_url),
            connectwise_client_id=req("HANDOVER_CW_CLIENT_ID"),
            itglue_site_summary_type_id=int(os.environ["HANDOVER_ITGLUE_SITE_SUMMARY_TYPE_ID"])
            if os.environ.get("HANDOVER_ITGLUE_SITE_SUMMARY_TYPE_ID") else None,
        )
