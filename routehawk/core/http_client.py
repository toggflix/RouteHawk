from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from routehawk.core.models import RulesConfig
from routehawk.core.scope import ScopeValidator


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str


class ScopeSafeHttpClient:
    """Small async HTTP wrapper that enforces scope before requesting URLs."""

    def __init__(self, scope: ScopeValidator, rules: Optional[RulesConfig] = None):
        self.scope = scope
        self.rules = rules or RulesConfig()

    async def get_text(self, url: str) -> HttpResponse:
        return await self.request_text("GET", url)

    async def post_text(self, url: str, body: str = "") -> HttpResponse:
        return await self.request_text("POST", url, body=body)

    async def request_text(self, method: str, url: str, body: str = "") -> HttpResponse:
        decision = self.scope.explain_url(url)
        if not decision.allowed:
            raise ValueError(f"Refusing out-of-scope request to {url}: {decision.reason}")

        import httpx

        async with httpx.AsyncClient(
            timeout=self.rules.timeout_seconds,
            follow_redirects=self.rules.follow_redirects,
            headers={"User-Agent": self.rules.user_agent},
        ) as client:
            response = await client.request(
                method,
                url,
                content=body,
                headers={"Content-Type": "application/json"} if method.upper() == "POST" else None,
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
