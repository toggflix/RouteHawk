from __future__ import annotations


def classify_status_code(status_code: int) -> str:
    if status_code == 200:
        return "public"
    if status_code in {301, 302, 303, 307, 308}:
        return "redirect"
    if status_code == 401:
        return "auth-required"
    if status_code == 403:
        return "forbidden"
    if status_code == 404:
        return "hidden-or-not-found"
    if status_code == 405:
        return "method-exists-maybe"
    if status_code >= 500:
        return "server-error-interesting"
    return "unknown"

