from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

from routehawk.core.models import SuppressionConfig


PATH_RE = re.compile(
    r"""(?P<path>
        (?:https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)
        |
        (?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)
    )""",
    re.VERBOSE,
)

METHOD_PREFIX_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/[^\s'\"`]+)", re.I)
PARAM_RE = re.compile(r"[:{]([A-Za-z_][A-Za-z0-9_]*)}?")
IGNORED_FILE_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
)
IGNORED_PATH_PREFIXES = (
    "/assets/",
    "/fonts/",
    "/images/",
    "/img/",
    "/media/",
    "/static/",
    "/vendor/",
)


@dataclass(frozen=True)
class ExtractedEndpoint:
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)


def extract_endpoints(text: str, suppression: Optional[SuppressionConfig] = None) -> List[ExtractedEndpoint]:
    seen: Set[str] = set()
    results: List[ExtractedEndpoint] = []

    for method, path in METHOD_PREFIX_RE.findall(text):
        cleaned = _clean_path(path)
        if _looks_useful(cleaned, suppression) and cleaned not in seen:
            seen.add(cleaned)
            results.append(
                ExtractedEndpoint(
                    path=cleaned,
                    method=method.upper(),
                    parameters=_extract_parameters(cleaned),
                )
            )

    for match in PATH_RE.finditer(text):
        if match.start() > 0 and text[match.start() - 1] == "<":
            continue
        cleaned = _clean_path(match.group("path"))
        if _looks_useful(cleaned, suppression) and cleaned not in seen:
            seen.add(cleaned)
            results.append(
                ExtractedEndpoint(
                    path=cleaned,
                    method="GET",
                    parameters=_extract_parameters(cleaned),
                )
            )

    return results


def _clean_path(path: str) -> str:
    path = path.strip().strip("'\"`,;)")
    if path.startswith("http://") or path.startswith("https://"):
        parsed = urlparse(path)
        rebuilt = parsed.path or "/"
        if parsed.query:
            rebuilt += "?" + parsed.query
        return rebuilt
    return path


def _looks_useful(path: str, suppression: Optional[SuppressionConfig] = None) -> bool:
    if not path.startswith("/"):
        return False
    if path.startswith("//"):
        return False
    if len(path) < 2:
        return False
    lowered = path.lower()
    path_only = lowered.split("?", 1)[0].split("#", 1)[0]
    suffixes = IGNORED_FILE_SUFFIXES + tuple(_normalize_suffixes(suppression))
    prefixes = IGNORED_PATH_PREFIXES + tuple(_normalize_prefixes(suppression))
    if any(path_only.endswith(suffix) for suffix in suffixes):
        return False
    if path_only.startswith(prefixes):
        return False
    if _matches_ignored_regex(path, suppression):
        return False
    return True


def _extract_parameters(path: str) -> List[str]:
    return sorted(set(PARAM_RE.findall(path)))


def unique_paths(endpoints: Iterable[ExtractedEndpoint]) -> List[str]:
    return sorted({endpoint.path for endpoint in endpoints})


def _normalize_suffixes(suppression: Optional[SuppressionConfig]) -> List[str]:
    if not suppression:
        return []
    return [value.lower() for value in suppression.ignore_suffixes if value]


def _normalize_prefixes(suppression: Optional[SuppressionConfig]) -> List[str]:
    if not suppression:
        return []
    return [value.lower() for value in suppression.ignore_path_prefixes if value]


def _matches_ignored_regex(path: str, suppression: Optional[SuppressionConfig]) -> bool:
    if not suppression:
        return False
    for pattern in suppression.ignore_regexes:
        if not pattern:
            continue
        try:
            if re.search(pattern, path):
                return True
        except re.error:
            continue
    return False
