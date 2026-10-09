"""Calling ConnectWise PSA and IT Glue within budget.

- One request budget per upstream system, shared by every user of the server.
- Bounded retries. A 429 is retried only if the wait it asks for (Retry-After)
  fits in the remaining time of the tool call; otherwise it is reported.
- Errors become `SourceUnavailable` with a short code. Upstream bodies and
  library messages are never propagated (they may carry data or secrets).
"""

from __future__ import annotations

import asyncio
import math
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from collections import deque
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx


class SourceUnavailable(Exception):
    def __init__(self, system: str, code: str, detail: str = "") -> None:
        super().__init__(f"{system}: {code}")
        self.system = system
        self.code = code
        self.detail = detail

    def public(self) -> dict:
        out = {"system": self.system, "status": "unavailable", "reason": self.code}
        if self.detail:
            out["detail"] = self.detail
        return out


class SharedBudget:
    """Sliding-window request budget for one upstream system, shared by all users."""

    def __init__(self, limit: int, window_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self._stamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def take(self) -> bool:
        async with self._lock:
            now = self.clock()
            while self._stamps and now - self._stamps[0] >= self.window_s:
                self._stamps.popleft()
            if len(self._stamps) >= self.limit:
                return False
            self._stamps.append(now)
            return True


@dataclass
class Deadline:
    at: float
    clock: Callable[[], float] = time.monotonic

    @classmethod
    def after(cls, seconds: float, clock: Callable[[], float] = time.monotonic) -> "Deadline":
        return cls(at=clock() + seconds, clock=clock)

    def remaining(self) -> float:
        return max(0.0, self.at - self.clock())


def _retry_after_seconds(resp: httpx.Response, now: Callable[[], float] = time.time) -> float | None:
    """Retry-After as delta-seconds or as an HTTP date (RFC 9110). None if absent or unreadable."""
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, when.timestamp() - now())
    if math.isnan(seconds) or math.isinf(seconds):
        return None
    return max(0.0, seconds)


async def send(
    client: httpx.AsyncClient,
    request: httpx.Request,
    *,
    system: str,
    budget: SharedBudget,
    deadline: Deadline,
    timeout_s: float,
    max_retries: int,
    max_retry_wait_s: float,
    max_bytes: int,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> httpx.Response:
    attempt = 0
    while True:
        if deadline.remaining() <= 0:
            raise SourceUnavailable(system, "deadline_exceeded", "The tool call ran out of time before this source answered.")
        if not await budget.take():
            raise SourceUnavailable(system, "request_budget_exhausted", "The shared request budget for this source is used up; try again in a few minutes.")
        try:
            resp = await asyncio.wait_for(client.send(request), timeout=min(timeout_s, deadline.remaining()))
        except (asyncio.TimeoutError, httpx.TimeoutException):
            if attempt < max_retries and deadline.remaining() > 0:
                attempt += 1
                continue
            raise SourceUnavailable(system, "timeout", "The source did not answer in time.") from None
        except httpx.HTTPError:
            raise SourceUnavailable(system, "connection_error", "The source could not be reached.") from None

        if resp.status_code == 429:
            asked = _retry_after_seconds(resp)
            wait = 1.0 * (2**attempt) if asked is None else asked
            if attempt < max_retries and wait <= max_retry_wait_s and wait < deadline.remaining():
                attempt += 1
                await sleep(wait)
                continue
            if asked is None:
                detail = (f"The source answered 429 Too Many Requests {attempt + 1} time(s) without a usable "
                          "Retry-After; gave up after a bounded backoff.")
            else:
                detail = f"The source asked to wait {asked:.0f}s (Retry-After); not retried within this call."
            raise SourceUnavailable(system, "rate_limited", detail)
        if resp.status_code >= 500:
            if attempt < max_retries and deadline.remaining() > 1.0:
                attempt += 1
                await sleep(min(0.5 * (2**attempt), deadline.remaining() / 2))
                continue
            raise SourceUnavailable(system, f"upstream_http_{resp.status_code}", "The source returned a server error.")
        if resp.status_code in (401, 403):
            raise SourceUnavailable(system, f"upstream_http_{resp.status_code}", "The source refused these credentials.")
        if resp.status_code == 404:
            raise SourceUnavailable(system, "not_found", "The source has no such record.")
        if resp.status_code >= 400:
            raise SourceUnavailable(system, f"upstream_http_{resp.status_code}", "The source rejected the request.")
        if len(resp.content) > max_bytes:
            raise SourceUnavailable(system, "response_too_large", "The source returned more data than this connector accepts in one page.")
        return resp
