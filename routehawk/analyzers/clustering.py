from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from routehawk.core.models import Asset


def cluster_assets_by_title(assets: Iterable[Asset]) -> Dict[str, List[Asset]]:
    clusters: Dict[str, List[Asset]] = defaultdict(list)
    for asset in assets:
        key = asset.title or "untitled"
        clusters[key].append(asset)
    return dict(clusters)

