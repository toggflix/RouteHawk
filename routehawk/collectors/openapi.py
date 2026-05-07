from __future__ import annotations

from typing import Dict, Iterable, List

from routehawk.analyzers.idor_candidates import score_endpoint
from routehawk.analyzers.route_classifier import classify_endpoint
from routehawk.analyzers.route_normalizer import normalize_path
from routehawk.core.models import Endpoint


COMMON_OPENAPI_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
]


def endpoints_from_openapi(spec: Dict[str, object], source_url: str) -> List[Endpoint]:
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return []

    endpoints: List[Endpoint] = []
    for path, operations in paths.items():
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method in _methods(operations.keys()):
            normalized = normalize_path(path)
            tags = classify_endpoint(method.upper(), normalized)
            endpoints.append(
                Endpoint(
                    source="openapi",
                    source_url=source_url,
                    method=method.upper(),
                    raw_path=path,
                    normalized_path=normalized,
                    tags=tags,
                    risk_score=score_endpoint(method.upper(), normalized, tags, source="openapi"),
                )
            )
    return endpoints


def _methods(keys: Iterable[str]) -> Iterable[str]:
    allowed = {"get", "post", "put", "patch", "delete", "options", "head"}
    return (key for key in keys if key.lower() in allowed)
