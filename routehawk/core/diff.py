from __future__ import annotations

from typing import Dict, Iterable, List, Optional


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
    changed_entries = []
    for key in unchanged_keys:
        changed_entry = _endpoint_change_summary(key, previous_map[key], current_map[key])
        if changed_entry is not None:
            changed_entries.append(changed_entry)
    previous_target = _target_value(previous)
    current_target = _target_value(current)
    previous_scope = _scope_values(previous)
    current_scope = _scope_values(current)
    target_changed = bool(previous_target and current_target and previous_target != current_target)
    scope_changed = bool(previous_scope and current_scope and previous_scope != current_scope)
    warning = ""
    if target_changed or scope_changed:
        warning = "Latest diff compares different targets or scopes; counts may not represent real endpoint drift."

    return {
        "new_count": len(new_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed_entries),
        "unchanged_count": len(unchanged_keys) - len(changed_entries),
        "new": [_endpoint_summary(current_map[key]) for key in new_keys],
        "removed": [_endpoint_summary(previous_map[key]) for key in removed_keys],
        "changed": changed_entries,
        "previous_target": previous_target,
        "current_target": current_target,
        "previous_scope": previous_scope,
        "current_scope": current_scope,
        "target_changed": target_changed,
        "scope_changed": scope_changed,
        "warning": warning,
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
    risk_reasons = _string_list(_list_values(endpoint.get("risk_reasons")))
    source_urls = _string_list(_list_values(endpoint.get("source_urls")))
    return {
        "endpoint": f"{method} {path}",
        "method": method,
        "path": path,
        "risk_score": _risk_score(endpoint),
        "extraction_confidence": _confidence(endpoint),
        "tags": _string_list(endpoint.get("tags", [])),
        "sources": _sources(endpoint),
        "source_urls_count": len(source_urls),
        "risk_reason_count": len(risk_reasons),
        "risk_reasons_preview": risk_reasons[:3],
    }


def _endpoint_change_summary(
    key: str,
    previous_endpoint: Dict[str, object],
    current_endpoint: Dict[str, object],
) -> Optional[Dict[str, object]]:
    deltas: Dict[str, object] = {}
    previous_score = _risk_score(previous_endpoint)
    current_score = _risk_score(current_endpoint)
    if previous_score != current_score:
        deltas["risk_score"] = {"previous": previous_score, "current": current_score}

    previous_confidence = _confidence(previous_endpoint)
    current_confidence = _confidence(current_endpoint)
    if previous_confidence != current_confidence:
        deltas["extraction_confidence"] = {
            "previous": previous_confidence,
            "current": current_confidence,
        }

    tags_delta = _list_delta(previous_endpoint.get("tags"), current_endpoint.get("tags"))
    if tags_delta:
        deltas["tags"] = tags_delta

    sources_delta = _list_delta(_sources(previous_endpoint), _sources(current_endpoint))
    if sources_delta:
        deltas["sources"] = sources_delta

    risk_reasons_delta = _list_delta(
        previous_endpoint.get("risk_reasons"),
        current_endpoint.get("risk_reasons"),
    )
    if risk_reasons_delta:
        deltas["risk_reasons"] = risk_reasons_delta

    source_urls_delta = _list_delta(
        previous_endpoint.get("source_urls"),
        current_endpoint.get("source_urls"),
    )
    if source_urls_delta:
        deltas["source_urls"] = source_urls_delta

    if not deltas:
        return None

    return {
        "endpoint": key,
        "previous_risk_score": previous_score,
        "current_risk_score": current_score,
        "previous": _endpoint_summary(previous_endpoint),
        "current": _endpoint_summary(current_endpoint),
        "changed_fields": sorted(deltas.keys()),
        "deltas": deltas,
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


def _confidence(endpoint: Dict[str, object]) -> str:
    value = str(endpoint.get("extraction_confidence") or "medium").lower()
    if value in {"high", "medium", "low"}:
        return value
    return "medium"


def _list_delta(previous: object, current: object) -> Optional[Dict[str, List[str]]]:
    previous_values = set(_string_list(_list_values(previous)))
    current_values = set(_string_list(_list_values(current)))
    added = sorted(current_values - previous_values)
    removed = sorted(previous_values - current_values)
    if not added and not removed:
        return None
    return {"added": added, "removed": removed}


def _list_values(value: object) -> List[object]:
    return value if isinstance(value, list) else []


def _string_list(values: Iterable[object]) -> List[str]:
    return sorted({str(value) for value in values if value is not None})


def _target_value(payload: Dict[str, object]) -> str:
    value = payload.get("target")
    return str(value).strip() if value is not None else ""


def _scope_values(payload: Dict[str, object]) -> List[str]:
    raw = payload.get("scope")
    if not isinstance(raw, list):
        return []
    return _string_list(raw)
