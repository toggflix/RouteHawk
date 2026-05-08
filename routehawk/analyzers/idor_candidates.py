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
    score, _ = score_endpoint_with_reasons(method, normalized_path, tags, source=source)
    return score


def score_endpoint_with_reasons(
    method: str,
    normalized_path: str,
    tags: Iterable[str],
    source: str = "",
) -> tuple[int, list[str]]:
    tag_set = set(tags)
    score = 0
    reasons = []

    if "object-reference" in tag_set:
        score += 30
        reasons.append("+30 object identifier pattern in normalized route")
    if tag_set.intersection({"billing", "user-object", "business-object", "data-export"}):
        score += 25
        reasons.append("+25 sensitive business or user resource keyword")
    if method.upper() in {"GET", "PUT", "PATCH", "DELETE"}:
        score += 15
        reasons.append(f"+15 method {method.upper()} often exposes object-level authz checks")
    if source == "javascript":
        score += 10
        reasons.append("+10 route discovered in frontend JavaScript")
    if source == "openapi":
        score += 15
        reasons.append("+15 route documented in OpenAPI/Swagger")
    if tag_set.intersection({"admin", "authorization"}):
        score += 25
        reasons.append("+25 admin/authorization keyword present")
    if tag_set.intersection({"internal", "debug"}):
        score += 20
        reasons.append("+20 internal/debug keyword present")
    if "graphql" in tag_set:
        score += 20
        reasons.append("+20 GraphQL endpoint behavior candidate")
    if "auth" in tag_set:
        score += 10
        reasons.append("+10 auth/session/token keyword present")
    if "?" in normalized_path:
        score += 5
        reasons.append("+5 query-based parameter surface")

    return min(score, 100), reasons


def endpoint_confidence(
    *,
    sources: Iterable[str],
    source_url_count: int,
    raw_path_count: int,
    parameter_count: int,
) -> str:
    source_set = {str(item) for item in sources if item}
    confidence_points = 0
    if "openapi" in source_set:
        confidence_points += 3
    if len(source_set) >= 2:
        confidence_points += 2
    if source_url_count >= 2:
        confidence_points += 1
    if raw_path_count >= 2:
        confidence_points += 1
    if parameter_count >= 1:
        confidence_points += 1
    if source_set.intersection({"javascript", "robots", "sitemap", "graphql"}):
        confidence_points += 1

    if confidence_points >= 5:
        return "high"
    if confidence_points >= 3:
        return "medium"
    return "low"


def severity_for_score(score: int) -> str:
    if score <= 30:
        return "info"
    if score <= 55:
        return "low"
    if score <= 75:
        return "medium"
    return "high"
