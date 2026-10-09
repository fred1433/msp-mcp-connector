"""The stated access policy.

The policy file says, for each principal, which clients it may see and which
IT Glue documents it may read. The connector enforces exactly this policy.
Whether it mirrors the real permissions of each PSA member and IT Glue user is
an acceptance task, listed in docs/authorization.md.

The file is re-read when it changes, so a revocation applies at the next request.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from .identity import Principal


class PolicyError(Exception):
    """Raised for a refusal. `code` is safe to show and to audit."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ClientLink:
    """One client across both systems. Never joined by name."""

    client_ref: str
    display_name: str
    psa_company_id: int
    itglue_organization_id: int


@dataclass(frozen=True)
class Grant:
    principal: Principal
    psa_credential: str
    clients: frozenset[str]
    documents: dict[str, frozenset[int]]


class Policy:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._mtime_ns: int | None = None
        self._data: dict = {}

    def _load(self) -> dict:
        with self._lock:
            mtime = self.path.stat().st_mtime_ns
            if mtime != self._mtime_ns:
                self._data = json.loads(self.path.read_text())
                self._mtime_ns = mtime
            return self._data

    @property
    def version(self) -> str:
        return str(self._load().get("version", "unversioned"))

    def is_active(self, principal: Principal) -> bool:
        data = self._load()
        if data.get("kill_switch"):
            return False
        if principal.key in set(data.get("disabled_principals", [])):
            return False
        return principal.key in data.get("principals", {})

    def grant(self, principal: Principal | None) -> Grant:
        if principal is None:
            raise PolicyError("unauthenticated", "No authenticated principal on this request.")
        if not self.is_active(principal):
            raise PolicyError("principal_not_allowed", "This identity is not enabled for the connector.")
        raw = self._load()["principals"][principal.key]
        return Grant(
            principal=principal,
            psa_credential=str(raw["psa_credential"]),
            clients=frozenset(raw.get("clients", [])),
            documents={k: frozenset(int(i) for i in v) for k, v in raw.get("documents", {}).items()},
        )

    def all_links(self) -> list[ClientLink]:
        return [
            ClientLink(
                client_ref=ref,
                display_name=str(c["display_name"]),
                psa_company_id=int(c["psa_company_id"]),
                itglue_organization_id=int(c["itglue_organization_id"]),
            )
            for ref, c in self._load().get("clients", {}).items()
        ]

    def link(self, grant: Grant, client_ref: str) -> ClientLink:
        if client_ref not in grant.clients:
            raise PolicyError("client_not_allowed", f"You are not authorized for client {client_ref}.")
        for link in self.all_links():
            if link.client_ref == client_ref:
                return link
        raise PolicyError("client_not_mapped", f"Client {client_ref} has no PSA/IT Glue mapping.")

    def document_allowed(self, grant: Grant, client_ref: str, document_id: int) -> bool:
        return document_id in grant.documents.get(client_ref, frozenset())
