from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ScopeConfig:
    domains: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class RulesConfig:
    follow_redirects: bool = True
    reject_out_of_scope_redirects: bool = True
    max_rps_per_host: int = 2
    max_concurrency: int = 20
    timeout_seconds: int = 10
    user_agent: str = "RouteHawk/0.1"
    max_retries: int = 2
    retry_backoff_seconds: float = 0.5
    respect_retry_after: bool = True


@dataclass(frozen=True)
class ScanOptions:
    passive_first: bool = True
    download_javascript: bool = True
    parse_openapi: bool = True
    parse_robots: bool = True
    parse_sitemap: bool = True
    check_common_metadata: bool = True
    check_auth_behavior: bool = False
    auth_probe_limit: int = 20


@dataclass(frozen=True)
class SuppressionConfig:
    ignore_suffixes: List[str] = field(default_factory=list)
    ignore_path_prefixes: List[str] = field(default_factory=list)
    ignore_regexes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class RouteHawkConfig:
    program: str
    scope: ScopeConfig
    rules: RulesConfig = field(default_factory=RulesConfig)
    scan: ScanOptions = field(default_factory=ScanOptions)
    suppression: SuppressionConfig = field(default_factory=SuppressionConfig)
    targets: List[str] = field(default_factory=list)


@dataclass
class Asset:
    host: str
    scheme: str
    ip: Optional[str] = None
    status: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class Endpoint:
    source: str
    source_url: str
    method: str
    raw_path: str
    normalized_path: str
    parameters: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_reasons: List[str] = field(default_factory=list)
    confidence: str = "medium"
    sources: List[str] = field(default_factory=list)
    source_urls: List[str] = field(default_factory=list)
    raw_paths: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class Finding:
    type: str
    severity: str
    target: str
    endpoint: str
    evidence: List[str] = field(default_factory=list)
    manual_check: List[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class JavaScriptFile:
    url: str
    sha256: str
    cache_path: str
    size: int
    endpoints_found: int = 0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class MetadataRecord:
    source: str
    url: str
    status: Optional[int] = None
    details: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scope: List[str]
    assets: List[Asset] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    javascript_files: List[JavaScriptFile] = field(default_factory=list)
    metadata: List[MetadataRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
