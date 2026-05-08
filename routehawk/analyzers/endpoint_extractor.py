from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

from routehawk.core.models import SuppressionConfig


PATH_RE = re.compile(
    r"""(?P<path>
        (?:https?://[A-Za-z0-9._~:/?#\[\]{}@!$&'()*+,;=%-]+)
        |
        (?:/[A-Za-z0-9._~:/?#\[\]{}@!$&'()*+,;=%-]+)
    )""",
    re.VERBOSE,
)

METHOD_PREFIX_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/[^\s'\"`]+)", re.I)
PARAM_RE = re.compile(r"[:{]([A-Za-z_][A-Za-z0-9_]*)}?")
JS_FUNCTION_CALL_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\s*\(")
JS_OPERATOR_NOISE = (" + ", " * ", "=>", "&&", "||")
REPO_STYLE_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
REPO_STYLE_PROJECT_RE = re.compile(r"^[a-z0-9._-]{2,60}$")
KNOWN_REPOSITORY_NOISE_OWNERS = {
    "microsoft",
    "twbs",
    "krzysu",
    "studio-42",
    "consortium",
}
KNOWN_DOCUMENTATION_TOKENS = (
    "rec-css3-selectors",
    "wd-dom-level",
    "ecma-script-binding.html",
)
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
    confidence: str = "low"


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
                    confidence="high",
                )
            )

    for match in PATH_RE.finditer(text):
        if match.start() > 0 and text[match.start() - 1] == "<":
            continue
        raw = match.group("path")
        cleaned = _clean_path(raw)
        if _looks_useful(cleaned, suppression) and cleaned not in seen:
            seen.add(cleaned)
            results.append(
                ExtractedEndpoint(
                    path=cleaned,
                    method="GET",
                    parameters=_extract_parameters(cleaned),
                    confidence=_path_confidence(cleaned, from_absolute=raw.startswith(("http://", "https://"))),
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
    if _looks_like_js_expression_noise(path, lowered):
        return False
    if _looks_like_third_party_documentation_noise(path, lowered):
        return False
    if _looks_like_repository_reference_noise(path):
        return False
    if _looks_like_vendor_telemetry_noise(path_only):
        return False
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


def _path_confidence(path: str, from_absolute: bool) -> str:
    if from_absolute:
        return "medium"
    lowered = path.lower()
    if "?" in path:
        return "medium"
    if lowered == "/graphql":
        return "medium"
    if lowered.endswith(".json"):
        return "medium"
    if lowered.startswith("/api/"):
        return "medium"
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) >= 3:
        return "medium"
    return "low"


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


def _looks_like_js_expression_noise(path: str, lowered: str) -> bool:
    if " " in path:
        return True
    if path.count("?") > 1:
        return True
    if "(" in path or ")" in path:
        return True
    if "jquery." in lowered:
        return True
    if ".isinteger(" in lowered:
        return True
    if any(token in path for token in JS_OPERATOR_NOISE):
        return True
    if JS_FUNCTION_CALL_RE.search(path):
        return True
    return False


def _looks_like_third_party_documentation_noise(path: str, lowered: str) -> bool:
    path_only = lowered.split("?", 1)[0].split("#", 1)[0]
    if any(token in path_only for token in KNOWN_DOCUMENTATION_TOKENS):
        return True
    if path_only.startswith("/tr/") and any(token in path_only for token in ("rec-", "wd-", "spec")):
        return True
    if path_only.startswith("/xml/") and "/namespace" in path_only:
        return True
    if path_only.startswith("/consortium/legal/"):
        return True
    return False


def _looks_like_repository_reference_noise(path: str) -> bool:
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    segments = [segment for segment in path_only.split("/") if segment]
    if len(segments) < 2:
        return False
    owner = segments[0]
    project = segments[1]
    owner_lower = owner.lower()
    project_lower = project.lower()

    if owner_lower in KNOWN_REPOSITORY_NOISE_OWNERS:
        if len(segments) == 2:
            return True
        if len(segments) >= 3 and segments[2].lower() in {"issues", "issue", "pull", "pulls"}:
            return True

    if len(segments) >= 3 and segments[2].lower() in {"issues", "issue", "pull", "pulls"}:
        if _looks_like_repo_owner(owner, owner_lower) and _looks_like_repo_project(project, project_lower):
            return True
    return False


def _looks_like_vendor_telemetry_noise(path_only: str) -> bool:
    lowered = path_only.lower()
    if lowered.startswith("/youtubei/v1/"):
        return True
    if lowered.startswith("/get/videoqualityreport/"):
        return True
    return False


def _looks_like_repo_owner(owner: str, owner_lower: str) -> bool:
    if owner_lower in KNOWN_REPOSITORY_NOISE_OWNERS:
        return True
    if REPO_STYLE_OWNER_RE.match(owner_lower) and (owner != owner_lower or "-" in owner_lower):
        return True
    return False


def _looks_like_repo_project(project: str, project_lower: str) -> bool:
    if "." in project or "-" in project:
        return True
    if REPO_STYLE_PROJECT_RE.match(project_lower) and project != project_lower:
        return True
    return False
