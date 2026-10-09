"""Content policy for free text and text fields.

Structured fields go out through per-field allowlists in the adapters. Free text
(ticket notes, document sections, Textbox and Text traits, ticket summaries)
cannot be allowlisted, so it passes through this policy, which errs on the side
of withholding:

- a line that mentions a secret word is withheld whole (password, passcode,
  passphrase, pass, pwd, pw, PIN, PSK, key, secret, token, credential(s), creds,
  MFA, OTP, backup/recovery/door code, "mot de passe");
- if that line ends with a label and no value ("Password:", "Wi-Fi key -"),
  the next non-empty line is withheld too;
- command lines that carry a password (`net user NAME VALUE`, `sshpass -p`,
  `-p VALUE` after a login, `user / value` after "admin") are withheld;
- PEM private keys are withheld, including an unterminated one;
- the result is capped at a length and the cut is flagged.

Every form listed here has a test in tests/test_content_policy.py. A secret
written with none of these words or shapes ("the usual one is Hunter2") is not
detected: that is the stated limit, see docs/authorization.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SECRET_WORDS = (
    r"pass(?:word|words|wd|phrase|code|codes)?|pwd|pw|pins?|psk|keys?|secrets?|tokens?|"
    r"credentials?|creds|mfa|otp|2fa|totp|(?:backup|recovery|door|alarm|gate|access)\s+codes?|"
    r"mot\s+de\s+passe|mdp|api[\s_-]?key|private[\s_-]?key"
)
_SECRET_WORD = re.compile(rf"(?i)(?<![a-z0-9])(?:{SECRET_WORDS})(?![a-z0-9])")
# Applied to a line already stripped of trailing spaces and Markdown emphasis, so no
# pattern needs a trailing `\s*`; patterns avoid nested or adjacent repetitions.
_ENDS_WITH_LABEL = re.compile(rf"(?i)(?:{SECRET_WORDS})[ \t]*(?:[:=\-]|\bis|\bset to)?$|[:=\-]$")
_COMMANDS = re.compile(
    r"(?i)\bnet[ \t]+user[ \t]+[^\s/]+[ \t]+\S|\bsshpass\b|\s-p[ \t]*\S|"
    r"\badmin[a-z]*:?[ \t]+(?:[^\s/]+[ \t]+)?/[ \t]*\S|/p(?:assword)?:\S"
)
_FENCE = ("```", "~~~")
MAX_INPUT_CHARS = 20_000  # every text is cut to this length before any regular expression runs
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)

REDACTED = "[line withheld by content policy: possible credential]"

# Field names that suggest a secret: such a field is omitted whatever its kind.
_SECRET_NAME = re.compile(
    r"(?i)pass|pwd|(?<![a-z])pins?(?![a-z])|psk|key|secret|credential|creds|token|mfa|otp|code"
)


def name_suggests_secret(*names: str | None) -> bool:
    return any(n and _SECRET_NAME.search(n) for n in names)


@dataclass
class Cleaned:
    text: str
    redacted: bool
    truncated: bool


def clean(text: str, max_chars: int) -> Cleaned:
    if not isinstance(text, str):
        raise TypeError("clean() accepts strings only")
    truncated = False
    if len(text) > MAX_INPUT_CHARS:
        text, truncated = text[:MAX_INPUT_CHARS], True
    redacted = False
    text, n = _PEM_BLOCK.subn(REDACTED, text)
    redacted |= n > 0
    out: list[str] = []
    withhold_next = False
    in_withheld_fence = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_withheld_fence:
            if stripped.startswith(_FENCE):
                in_withheld_fence = False
            continue
        if withhold_next and stripped:
            withhold_next = False
            redacted = True
            if stripped.startswith(_FENCE):
                in_withheld_fence = True  # a label followed by a code block: the whole block goes
            out.append(REDACTED)
            continue
        if line == REDACTED:
            out.append(line)
            continue
        if _SECRET_WORD.search(line) or _COMMANDS.search(line):
            out.append(REDACTED)
            redacted = True
            bare = line.rstrip(" \t*_`#>|")
            withhold_next = bool(_ENDS_WITH_LABEL.search(bare))
            continue
        out.append(line)
    result = "\n".join(out).strip()
    if len(result) > max_chars:
        result = result[: max(0, max_chars - 1)].rstrip() + "…"
        truncated = True
    return Cleaned(result, redacted, truncated)


def clean_free_text(text: str, max_chars: int) -> tuple[str, bool]:
    """Backwards-compatible helper: (text, modified)."""
    c = clean(text, max_chars)
    return c.text, c.redacted or c.truncated


def cap(value: str | None, max_chars: int) -> str | None:
    if value is None or len(value) <= max_chars:
        return value
    return value[: max_chars - 1] + "…"
