from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx

from routehawk.core.models import RulesConfig
from routehawk.core.scope import ScopeValidator


RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS"}


class RequestBudgetExceeded(RuntimeError):
    """Raised when the configured per-scan request budget is exceeded."""


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str


class ScopeSafeHttpClient:
    """Polite async HTTP wrapper with scope checks, host rate limiting, and bounded retries."""

    def __init__(self, scope: ScopeValidator, rules: Optional[RulesConfig] = None):
        self.scope = scope
        self.rules = rules or RulesConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(max(1, int(self.rules.max_concurrency)))
        self._rate_lock = asyncio.Lock()
        self._next_request_at: Dict[str, float] = {}
        self._request_count = 0

    async def get_text(self, url: str) -> HttpResponse:
        return await self.request_text("GET", url)

    async def post_text(self, url: str, body: str = "") -> HttpResponse:
        return await self.request_text("POST", url, body=body)

    async def request_text(self, method: str, url: str, body: str = "") -> HttpResponse:
        normalized_method = method.upper()
        self._assert_in_scope(url)
        attempts = max(0, int(self.rules.max_retries)) + 1

        for attempt in range(attempts):
            self._consume_request_budget()
            await self._respect_host_rate_limit(url)
            try:
                response = await self._send_request(normalized_method, url, body=body)
            except (httpx.TimeoutException, httpx.TransportError):
                if not self._should_retry(normalized_method, None, attempt, attempts):
                    raise
                await asyncio.sleep(self._retry_delay(attempt, None))
                continue

            if self.rules.reject_out_of_scope_redirects:
                self._assert_in_scope(str(response.url), redirect=True)

            if self._should_retry(normalized_method, response, attempt, attempts):
                await asyncio.sleep(self._retry_delay(attempt, response))
                continue

            return HttpResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
            )

        raise RuntimeError(f"HTTP request retries exhausted for {normalized_method} {url}")

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _send_request(self, method: str, url: str, body: str = "") -> httpx.Response:
        client = await self._ensure_client()
        request_headers = {"Content-Type": "application/json"} if method == "POST" else None
        async with self._semaphore:
            return await client.request(method, url, content=body, headers=request_headers)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.rules.timeout_seconds,
                follow_redirects=self.rules.follow_redirects,
                headers={"User-Agent": self.rules.user_agent},
            )
        return self._client

    def _assert_in_scope(self, url: str, redirect: bool = False) -> None:
        decision = self.scope.explain_url(url)
        if decision.allowed:
            return
        if redirect:
            raise ValueError(f"Refusing out-of-scope redirect to {url}: {decision.reason}")
        raise ValueError(f"Refusing out-of-scope request to {url}: {decision.reason}")

    async def _respect_host_rate_limit(self, url: str) -> None:
        max_rps = float(self.rules.max_rps_per_host)
        if max_rps <= 0:
            return
        interval_seconds = 1.0 / max_rps
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return

        while True:
            async with self._rate_lock:
                now = time.monotonic()
                next_allowed = self._next_request_at.get(host, 0.0)
                wait_for = next_allowed - now
                if wait_for <= 0:
                    self._next_request_at[host] = now + interval_seconds
                    return
            await asyncio.sleep(wait_for)

    def _should_retry(
        self,
        method: str,
        response: Optional[httpx.Response],
        attempt: int,
        total_attempts: int,
    ) -> bool:
        if attempt >= (total_attempts - 1):
            return False
        if method not in IDEMPOTENT_METHODS:
            return False
        if response is None:
            return True
        return response.status_code in RETRYABLE_STATUS_CODES

    def _retry_delay(self, attempt: int, response: Optional[httpx.Response]) -> float:
        if (
            response is not None
            and self.rules.respect_retry_after
            and response.status_code in {429, 503}
        ):
            retry_after = self._parse_retry_after(response.headers.get("Retry-After", ""))
            if retry_after is not None:
                return max(0.0, min(retry_after, 30.0))
        base = max(0.05, float(self.rules.retry_backoff_seconds))
        return min(base * (2 ** attempt), 10.0)

    @staticmethod
    def _parse_retry_after(value: str) -> Optional[float]:
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            pass
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0.0, (parsed - now).total_seconds())

    def _consume_request_budget(self) -> None:
        budget = int(self.rules.request_budget_per_scan)
        if budget <= 0:
            self._request_count += 1
            return
        if self._request_count >= budget:
            raise RequestBudgetExceeded("Request budget exceeded for this scan")
        self._request_count += 1
