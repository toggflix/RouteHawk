from __future__ import annotations

import json
from typing import List, Optional
from urllib.parse import urlparse

from routehawk.core.models import Asset


def import_httpx_json(text: str) -> List[Asset]:
    assets = []
    for item in _json_records(text):
        url = str(item.get("url") or item.get("input") or "")
        parsed = urlparse(url)
        host = str(item.get("host") or parsed.hostname or "")
        if not host:
            continue
        assets.append(
            Asset(
                host=host,
                scheme=parsed.scheme or str(item.get("scheme") or "https"),
                status=_int(item.get("status_code")),
                title=str(item.get("title") or "") or None,
                technologies=_technologies(item),
            )
        )
    return assets


def _json_records(text: str) -> List[dict]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        loaded = json.loads(stripped)
        return [item for item in loaded if isinstance(item, dict)] if isinstance(loaded, list) else []
    records = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            records.append(loaded)
    return records


def _technologies(item: dict) -> List[str]:
    tech = item.get("tech") or item.get("technologies") or []
    if isinstance(tech, list):
        return [str(value) for value in tech]
    if isinstance(tech, str):
        return [tech]
    return []


def _int(value: object) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
