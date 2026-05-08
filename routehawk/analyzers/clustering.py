from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, Iterable, List

from routehawk.core.models import Asset, Endpoint


def cluster_assets_by_title(assets: Iterable[Asset]) -> Dict[str, List[Asset]]:
    clusters: Dict[str, List[Asset]] = defaultdict(list)
    for asset in assets:
        key = asset.title or "untitled"
        clusters[key].append(asset)
    return dict(clusters)


@dataclass(frozen=True)
class RouteGroup:
    prefix: str
    count: int
    max_risk_score: int
    methods: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


def cluster_endpoints_by_prefix(endpoints: Iterable[Endpoint], depth: int = 2) -> List[RouteGroup]:
    grouped: Dict[str, List[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        grouped[_route_prefix(endpoint.normalized_path, depth)].append(endpoint)

    groups = []
    for prefix, items in grouped.items():
        methods = sorted({item.method for item in items})
        tags = sorted({tag for item in items for tag in item.tags})
        groups.append(
            RouteGroup(
                prefix=prefix,
                count=len(items),
                max_risk_score=max((item.risk_score for item in items), default=0),
                methods=methods,
                tags=tags,
            )
        )
    return sorted(groups, key=lambda item: (item.max_risk_score, item.count, item.prefix), reverse=True)


def _route_prefix(path: str, depth: int) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "/"
    return "/" + "/".join(parts[: max(1, depth)])
