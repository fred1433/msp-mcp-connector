"""Content policy for free text (ticket notes, document excerpts).

Structured fields go out through per-field allowlists in the adapters. Free
text cannot be allowlisted field by field, so it passes through this separate
policy: lines that look like credentials are replaced, and length is capped.
This is a safety net, not a guarantee; see docs/authorization.md.
"""

from __future__ import annotations

import re

_CREDENTIAL_LINE = re.compile(
    r"(?i)\b(pass(word|wd|phrase)?|pwd|pw|secret|api[ _-]?key|token|private[ _-]?key|pin|mfa|otp|recovery code)\b\s*[:=]"
)
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)

REDACTED = "[line withheld by content policy: possible credential]"


def clean_free_text(text: str, max_chars: int) -> tuple[str, bool]:
    """Return (clean_text, was_modified)."""
    modified = False
    text = _PEM.sub(REDACTED, text)
    lines = []
    for line in text.splitlines():
        if _CREDENTIAL_LINE.search(line):
            lines.append(REDACTED)
            modified = True
        else:
            lines.append(line)
    out = "\n".join(lines).strip()
    if len(out) > max_chars:
        out = out[: max_chars - 1].rstrip() + "…"
        modified = True
    return out, modified
