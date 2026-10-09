"""Per-principal upstream credentials for ConnectWise PSA.

Each principal maps to the API member credentials of that technician. If a
principal has no credential set, the call is refused: there is no shared
fallback key. The demo ships synthetic credential sets only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .policy import PolicyError


@dataclass(frozen=True)
class PsaCredential:
    company_id: str  # the MSP's PSA login company, not a client's company id
    public_key: str
    private_key: str

    def __repr__(self) -> str:  # never print key material
        return f"PsaCredential(company_id={self.company_id!r}, public_key=***, private_key=***)"


class CredentialStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def psa(self, name: str) -> PsaCredential:
        data = json.loads(self.path.read_text())
        raw = data.get(name)
        if not raw:
            raise PolicyError("no_psa_credentials", "No ConnectWise credentials are registered for this identity.")
        return PsaCredential(company_id=raw["company_id"], public_key=raw["public_key"], private_key=raw["private_key"])
