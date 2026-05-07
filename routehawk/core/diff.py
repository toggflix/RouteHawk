from __future__ import annotations

from typing import Dict, Iterable, List


def endpoint_key(endpoint: Dict[str, object]) -> str:
    method = str(endpoint.get("method") or "GET").upper()
    path = str(endpoint.get("normalized_path") or endpoint.get("raw_path") or "")
    return f"{method} {path}"


def build_endpoint_diff(previous: Dict[str, object], current: Dict[str, object]) -> Dict[str, object]:
    previous_map = _endpoint_map(previous.get("endpoints", []))
    current_map = _endpoint_map(current.get("endpoints", []))

    previous_keys = set(previous_map)
    current_keys = set(current_map)
    new_keys = sorted(current_keys - previous_keys)
    removed_keys = sorted(previous_keys - current_keys)
    unchanged_keys = sorted(current_keys & previous_keys)
    changed_keys = [
        key for key in unchanged_keys if _risk_score(previous_map[key]) != _risk_score(current_map[key])
    ]

    return {
        "new_count": len(new_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed_keys),
        "unchanged_count": len(unchanged_keys) - len(changed_keys),
        "new": [_endpoint_summary(current_map[key]) for key in new_keys],
        "removed": [_endpoint_summary(previous_map[key]) for key in removed_keys],
        "changed": [
            {
                "endpoint": key,
                "previous_risk_score": _risk_score(previous_map[key]),
                "current_risk_score": _risk_score(current_map[key]),
                "current": _endpoint_summary(current_map[key]),
            }
            for key in changed_keys
        ],
    }


def _endpoint_map(endpoints: object) -> Dict[str, Dict[str, object]]:
    if not isinstance(endpoints, list):
        return {}

    mapped: Dict[str, Dict[str, object]] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        key = endpoint_key(endpoint)
        if key.strip():
            mapped[key] = endpoint
    return mapped


def _endpoint_summary(endpoint: Dict[str, object]) -> Dict[str, object]:
    path = str(endpoint.get("normalized_path") or endpoint.get("raw_path") or "")
    method = str(endpoint.get("method") or "GET").upper()
    return {
        "endpoint": f"{method} {path}",
        "method": method,
        "path": path,
        "risk_score": _risk_score(endpoint),
        "tags": _string_list(endpoint.get("tags", [])),
        "sources": _sources(endpoint),
    }


def _risk_score(endpoint: Dict[str, object]) -> int:
    try:
        return int(endpoint.get("risk_score", 0))
    except (TypeError, ValueError):
        return 0


def _sources(endpoint: Dict[str, object]) -> List[str]:
    sources = endpoint.get("sources")
    if isinstance(sources, list) and sources:
        return _string_list(sources)
    source = endpoint.get("source")
    return [str(source)] if source else ["unknown"]


def _string_list(values: Iterable[object]) -> List[str]:
    return sorted({str(value) for value in values if value is not None})
