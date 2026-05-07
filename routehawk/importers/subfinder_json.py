from __future__ import annotations

import json
from typing import List


def import_subfinder_json(text: str) -> List[str]:
    hosts = []
    stripped = text.strip()
    if not stripped:
        return hosts

    if stripped.startswith("["):
        loaded = json.loads(stripped)
        if isinstance(loaded, list):
            for item in loaded:
                host = _host_from_item(item)
                if host:
                    hosts.append(host)
    else:
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                item = line
            host = _host_from_item(item)
            if host:
                hosts.append(host)

    return sorted(set(hosts))


def _host_from_item(item: object) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        for key in ("host", "input", "domain"):
            value = str(item.get(key) or "").strip()
            if value:
                return value
    return ""
