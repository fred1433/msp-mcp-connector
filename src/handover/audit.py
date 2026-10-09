"""Append-only audit log, one JSON object per tool call.

Recorded: principal, client reference, tool, source record IDs, decision,
reason code, policy version, timestamp, correlation ID.
Never recorded: record content, ticket or note text, credentials, upstream
response bodies, exception messages from upstream libraries.
"""

from __future__ import annotations

import json
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

ALLOWED_KEYS = {
    "ts", "correlation_id", "principal", "client_ref", "tool", "decision",
    "reason", "policy_version", "source_ids", "sources_unavailable",
}


class AuditLog:
    def __init__(self, path: Path | None = None, stream: TextIO | None = None) -> None:
        self.path = Path(path) if path else None
        self.stream = stream if stream is not None else (None if path else sys.stderr)
        self._lock = threading.Lock()
        self.records: list[dict] = []  # in-memory copy, used by tests and the demo trace

    @staticmethod
    def new_correlation_id() -> str:
        return uuid.uuid4().hex

    def record(
        self,
        *,
        correlation_id: str,
        principal: str | None,
        client_ref: str | None,
        tool: str,
        decision: str,
        reason: str,
        policy_version: str,
        source_ids: list[str] | None = None,
        sources_unavailable: list[str] | None = None,
    ) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "correlation_id": correlation_id,
            "principal": principal,
            "client_ref": client_ref,
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "policy_version": policy_version,
            "source_ids": sorted(source_ids or []),
            "sources_unavailable": sorted(sources_unavailable or []),
        }
        assert set(entry) == ALLOWED_KEYS
        line = json.dumps(entry, sort_keys=True)
        with self._lock:
            self.records.append(entry)
            if self.path:
                with self.path.open("a") as fh:
                    fh.write(line + "\n")
            elif self.stream is not None:
                self.stream.write(line + "\n")
        return entry
