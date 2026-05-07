from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
INT_RE = re.compile(r"^\d+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{24,}$")
EMAIL_RE = re.compile(r"^[^@\s/]+@[^@\s/]+\.[^@\s/]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")


def normalize_path(path: str) -> str:
    split = urlsplit(path)
    segments = [_normalize_segment(segment) for segment in split.path.split("/")]
    normalized_path = "/".join(segments)

    if split.query:
        query_keys = sorted(key for key, _ in parse_qsl(split.query, keep_blank_values=True))
        normalized_query = "&".join(f"{key}={{value}}" for key in query_keys)
    else:
        normalized_query = ""

    return urlunsplit(("", "", normalized_path, normalized_query, ""))


def _normalize_segment(segment: str) -> str:
    if not segment:
        return segment
    if segment.startswith("{") and segment.endswith("}"):
        return segment
    if segment.startswith(":") and len(segment) > 1:
        return "{" + segment[1:] + "}"
    if UUID_RE.match(segment):
        return "{uuid}"
    if INT_RE.match(segment):
        return "{id}"
    if EMAIL_RE.match(segment):
        return "{email}"
    if HEX_RE.match(segment):
        return "{hash}"
    if TOKEN_RE.match(segment):
        return "{token}"
    return segment

