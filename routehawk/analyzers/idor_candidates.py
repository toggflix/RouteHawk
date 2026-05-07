from __future__ import annotations

from typing import Iterable


MANUAL_IDOR_CHECKLIST = [
    "Login as User A.",
    "Capture a valid request for the endpoint.",
    "Replace the object identifier with another user's known identifier.",
    "Check status code, response body, and ownership enforcement.",
    "Repeat with read and write methods when authorized by the program rules.",
]

ADMIN_AUTHZ_CHECKLIST = [
    "Confirm the route is inside the authorized program scope.",
    "Request the endpoint as a low-privileged authenticated user.",
    "Compare behavior with an admin or authorized role when available.",
    "Check whether role and permission enforcement happens server-side.",
    "Review response codes, redirects, and partial data disclosure.",
]

INTERNAL_DEBUG_CHECKLIST = [
    "Confirm the route is intentionally exposed to the tested environment.",
    "Request the endpoint without credentials and with a low-privileged session.",
    "Check for environment names, secrets, tokens, stack traces, or internal hostnames.",
    "Verify whether the endpoint leaks operational metrics or configuration values.",
    "Document only evidence and avoid changing server state.",
]

GRAPHQL_CHECKLIST = [
    "Confirm the endpoint accepts GraphQL-shaped requests without aggressive probing.",
    "Check whether unauthenticated requests reveal schema or resolver error details.",
    "Compare authorization behavior across low-privileged and authorized sessions.",
    "Review object identifier arguments for ownership enforcement candidates.",
    "Avoid repeated introspection or heavy queries unless explicitly allowed.",
]


def score_endpoint(method: str, normalized_path: str, tags: Iterable[str], source: str = "") -> int:
    tag_set = set(tags)
    score = 0

    if "object-reference" in tag_set:
        score += 30
    if tag_set.intersection({"billing", "user-object", "business-object", "data-export"}):
        score += 25
    if method.upper() in {"GET", "PUT", "PATCH", "DELETE"}:
        score += 15
    if source == "javascript":
        score += 10
    if source == "openapi":
        score += 15
    if tag_set.intersection({"admin", "authorization"}):
        score += 25
    if tag_set.intersection({"internal", "debug"}):
        score += 20
    if "graphql" in tag_set:
        score += 20
    if "auth" in tag_set:
        score += 10
    if "?" in normalized_path:
        score += 5

    return min(score, 100)


def severity_for_score(score: int) -> str:
    if score <= 30:
        return "info"
    if score <= 55:
        return "low"
    if score <= 75:
        return "medium"
    return "high"
