from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional
from urllib.parse import urlparse

from routehawk.core.models import RulesConfig
from routehawk.core.scope import ScopeValidator


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str


class ScopeSafeHttpClient:
    """Small async HTTP wrapper that enforces scope and low-impact request limits."""

    def __init__(
        self,
        scope: ScopeValidator,
        rules: Optional[RulesConfig] = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.scope = scope
        self.rules = rules or RulesConfig()
        self._clock = clock
        self._sleep = sleep
        self._request_semaphore = asyncio.Semaphore(max(1, int(self.rules.max_concurrency or 1)))
        self._host_locks: Dict[str, asyncio.Lock] = {}
        self._last_request_at: Dict[str, float] = {}

    async def get_text(self, url: str) -> HttpResponse:
        return await self.request_text("GET", url)

    async def post_text(self, url: str, body: str = "") -> HttpResponse:
        return await self.request_text("POST", url, body=body)

    async def request_text(self, method: str, url: str, body: str = "") -> HttpResponse:
        decision = self.scope.explain_url(url)
        if not decision.allowed:
            raise ValueError(f"Refusing out-of-scope request to {url}: {decision.reason}")

        async with self._request_semaphore:
            await self._respect_host_rate_limit(url)
            return await self._send_request(method, url, body)

    async def _send_request(self, method: str, url: str, body: str = "") -> HttpResponse:
        import httpx

        request_headers = {"Content-Type": "application/json"} if method.upper() == "POST" else None

        async with httpx.AsyncClient(
            timeout=self.rules.timeout_seconds,
            follow_redirects=self.rules.follow_redirects,
            headers={"User-Agent": self.rules.user_agent},
        ) as client:
            response = await client.request(
                method,
                url,
                content=body,
                headers=request_headers,
            )
            if self.rules.reject_out_of_scope_redirects:
                final_decision = self.scope.explain_url(str(response.url))
                if not final_decision.allowed:
                    raise ValueError(
                        f"Refusing out-of-scope redirect to {response.url}: {final_decision.reason}"
                    )
            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
            )

    async def _respect_host_rate_limit(self, url: str) -> None:
        max_rps = int(self.rules.max_rps_per_host or 0)
        if max_rps <= 0:
            return

        host = _host_key(url)
        if not host:
            return

        lock = self._host_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._host_locks[host] = lock

        minimum_interval = 1.0 / max_rps
        async with lock:
            now = self._clock()
            last_request_at = self._last_request_at.get(host)
            if last_request_at is not None:
                wait_seconds = (last_request_at + minimum_interval) - now
                if wait_seconds > 0:
                    await self._sleep(wait_seconds)
                    now = max(self._clock(), last_request_at + minimum_interval)
            self._last_request_at[host] = now


def _host_key(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{hostname.lower()}{port}"
