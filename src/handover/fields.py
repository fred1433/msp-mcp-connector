"""Typed output fields.

Every field a tool returns is built here. Each parser enforces its type: text
(through the content policy), integer id, ISO 8601 date, typed list. A value of
the wrong type (an object or a list in a scalar field, a number where text is
expected) is omitted and the omission is reported in the record, never coerced
with str().
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .content import clean

MAX_TEXT = 300
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?(?:Z|[+-]\d{2}:?\d{2})?$")


def as_id(value: Any) -> int | None:
    """An upstream id: a non-negative int, or a string of digits (JSON:API ids are strings). Never a bool."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit() and len(value) <= 18:
        return int(value)
    return None


def as_date(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40 or not _ISO.match(value):
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


class Record:
    """Builds one output record and keeps track of what was omitted, withheld or cut."""

    def __init__(self) -> None:
        self.out: dict[str, Any] = {}
        self.malformed: list[str] = []
        self.redacted: list[str] = []
        self.truncated: list[str] = []

    def text(self, key: str, value: Any, max_chars: int = MAX_TEXT) -> None:
        if value is None:
            return
        if not isinstance(value, str):
            self.malformed.append(key)
            return
        c = clean(value, max_chars)
        self.out[key] = c.text
        if c.redacted:
            self.redacted.append(key)
        if c.truncated:
            self.truncated.append(key)

    def ident(self, key: str, value: Any) -> None:
        if value is None:
            return
        v = as_id(value)
        if v is None:
            self.malformed.append(key)
        else:
            self.out[key] = v

    def date(self, key: str, value: Any) -> None:
        if value is None:
            return
        v = as_date(value)
        if v is None:
            self.malformed.append(key)
        else:
            self.out[key] = v

    def text_list(self, key: str, values: Any, max_items: int, max_chars: int = MAX_TEXT) -> None:
        if values is None:
            return
        if not isinstance(values, list):
            self.malformed.append(key)
            return
        items = []
        for v in values[:max_items]:
            if not isinstance(v, str):
                self.malformed.append(key)
                continue
            c = clean(v, max_chars)
            if c.redacted:
                self.redacted.append(key)
                continue  # a withheld list item is dropped, not shown as a placeholder
            if c.truncated:
                self.truncated.append(key)
            items.append(c.text)
        if len(values) > max_items:
            self.truncated.append(key)
        self.out[key] = items

    def scalar(self, key: str, value: Any) -> None:
        """Number or boolean (Number, Percent, Checkbox traits)."""
        if value is None:
            return
        if isinstance(value, bool) or (isinstance(value, (int, float)) and value == value):
            self.out[key] = value
        else:
            self.malformed.append(key)

    def done(self) -> dict[str, Any]:
        if self.malformed:
            self.out["omitted_malformed_fields"] = sorted(set(self.malformed))
        if self.redacted:
            self.out["content_policy_applied"] = sorted(set(self.redacted))
        if self.truncated:
            self.out["truncated_fields"] = sorted(set(self.truncated))
        return self.out
