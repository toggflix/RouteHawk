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
        if parsed.port is not None:
            decision = self.explain_host(f"{parsed.hostname}:{parsed.port}")
            if decision.allowed:
                return decision
        return self.explain_host(parsed.hostname)

    def explain_host(self, host: str) -> ScopeDecision:
        normalized = self._clean_domain(host)
        host_only = _host_without_port(normalized)
        if self._looks_like_ip(host_only):
            return self._explain_ip(host_only)

        for pattern in self.domains:
            if pattern.startswith("*."):
                parent = pattern[2:]
                if host_only.endswith("." + parent) and host_only != parent:
                    return ScopeDecision(True, f"Matched wildcard scope {pattern}")
                continue

            if ":" in pattern:
                candidate = normalized
            else:
                candidate = host_only
            if candidate == pattern:
                return ScopeDecision(True, f"Matched exact scope {pattern}")

        return ScopeDecision(False, "Hostname is outside configured scope")

    @staticmethod
    def _clean_domain(value: str) -> str:
        return normalize_scope_entry(value)

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


def normalize_scope_entries(entries: Iterable[str]) -> tuple[List[str], List[str]]:
    normalized: List[str] = []
    notes: List[str] = []
    seen = set()
    for raw in entries:
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        value = normalize_scope_entry(candidate)
        if not value:
            continue
        if value not in seen:
            seen.add(value)
            normalized.append(value)
        if value != candidate:
            notes.append(f"Normalized scope entry: {candidate} -> {value}")
    return normalized, notes


def normalize_scope_entry(value: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""

    wildcard = cleaned.startswith("*.")
    body = cleaned[2:] if wildcard else cleaned
    normalized_body = _normalize_scope_body(body)
    if not normalized_body:
        return ""
    return f"*.{normalized_body}" if wildcard else normalized_body


def _normalize_scope_body(value: str) -> str:
    cleaned = value.strip().rstrip(".")
    if not cleaned:
        return ""

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            if parsed.port is not None:
                return f"{host}:{parsed.port}"
            return host

    if cleaned.startswith("//"):
        parsed = urlparse(f"http:{cleaned}")
        if parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            if parsed.port is not None:
                return f"{host}:{parsed.port}"
            return host

    host_candidate = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return host_candidate.lower().rstrip(".")


def _host_without_port(value: str) -> str:
    if value.count(":") == 1 and not value.startswith("["):
        return value.rsplit(":", 1)[0]
    return value
