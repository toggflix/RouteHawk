from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List

from routehawk.analyzers.clustering import RouteGroup, cluster_endpoints_by_prefix
from routehawk.analyzers.idor_candidates import severity_for_score
from routehawk.core.models import Endpoint, ScanResult


@dataclass(frozen=True)
class ReportSummary:
    endpoint_count: int
    asset_count: int
    finding_count: int
    warning_count: int
    javascript_file_count: int
    metadata_count: int
    high_risk_count: int
    medium_risk_count: int
    source_counts: Dict[str, int] = field(default_factory=dict)
    tag_counts: Dict[str, int] = field(default_factory=dict)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    top_endpoints: List[Endpoint] = field(default_factory=list)
    route_groups: List[RouteGroup] = field(default_factory=list)


def build_summary(result: ScanResult) -> ReportSummary:
    source_counter: Counter[str] = Counter()
    tag_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()

    for endpoint in result.endpoints:
        sources = endpoint.sources or [endpoint.source]
        source_counter.update(sources)
        tag_counter.update(endpoint.tags)
        severity_counter.update([severity_for_score(endpoint.risk_score)])

    high_risk = sum(1 for endpoint in result.endpoints if severity_for_score(endpoint.risk_score) == "high")
    medium_risk = sum(
        1 for endpoint in result.endpoints if severity_for_score(endpoint.risk_score) == "medium"
    )

    return ReportSummary(
        endpoint_count=len(result.endpoints),
        asset_count=len(result.assets),
        finding_count=len(result.findings),
        warning_count=len(result.warnings),
        javascript_file_count=len(result.javascript_files),
        metadata_count=len(result.metadata),
        high_risk_count=high_risk,
        medium_risk_count=medium_risk,
        source_counts=dict(sorted(source_counter.items())),
        tag_counts=dict(tag_counter.most_common()),
        severity_counts=dict(sorted(severity_counter.items())),
        top_endpoints=sorted(result.endpoints, key=lambda item: item.risk_score, reverse=True)[:8],
        route_groups=cluster_endpoints_by_prefix(result.endpoints)[:10],
    )
