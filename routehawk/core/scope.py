from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeValidator:
    """Validates URLs and hostnames against explicit domain scope entries."""

    def __init__(self, domains: Iterable[str], cidrs: Iterable[str] = ()):
        self.domains = [self._clean_domain(item) for item in domains if item]
        self.cidrs = [ipaddress.ip_network(item, strict=False) for item in cidrs if item]

    def is_url_allowed(self, url: str) -> bool:
        return self.explain_url(url).allowed

    def is_host_allowed(self, host: str) -> bool:
        return self.explain_host(host).allowed

    def explain_url(self, url: str) -> ScopeDecision:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return ScopeDecision(False, "URL scheme is not HTTP or HTTPS")
        if not parsed.hostname:
            return ScopeDecision(False, "URL does not contain a hostname")
        return self.explain_host(parsed.hostname)

    def explain_host(self, host: str) -> ScopeDecision:
        normalized = self._clean_domain(host)
        if self._looks_like_ip(normalized):
            return self._explain_ip(normalized)

        for pattern in self.domains:
            if pattern.startswith("*."):
                parent = pattern[2:]
                if normalized.endswith("." + parent) and normalized != parent:
                    return ScopeDecision(True, f"Matched wildcard scope {pattern}")
                continue

            if normalized == pattern:
                return ScopeDecision(True, f"Matched exact scope {pattern}")

        return ScopeDecision(False, "Hostname is outside configured scope")

    @staticmethod
    def _clean_domain(value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if "://" in value:
            parsed = urlparse(value)
            return (parsed.hostname or value).lower().rstrip(".")
        return value

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _explain_ip(self, value: str) -> ScopeDecision:
        ip = ipaddress.ip_address(value)
        for network in self.cidrs:
            if ip in network:
                return ScopeDecision(True, f"Matched CIDR scope {network}")
        return ScopeDecision(False, "IP address is outside configured CIDR scope")


def reject_out_of_scope_redirects(redirect_chain: List[str], validator: ScopeValidator) -> ScopeDecision:
    for url in redirect_chain:
        decision = validator.explain_url(url)
        if not decision.allowed:
            return ScopeDecision(False, f"Redirect leaves scope at {url}: {decision.reason}")
    return ScopeDecision(True, "Redirect chain stayed in scope")

