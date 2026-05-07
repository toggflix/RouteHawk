from __future__ import annotations

from typing import Dict, List


def fingerprint_headers(headers: Dict[str, str]) -> List[str]:
    technologies = []
    lowered = {key.lower(): value.lower() for key, value in headers.items()}
    server = lowered.get("server", "")
    powered_by = lowered.get("x-powered-by", "")

    for marker in ("nginx", "apache", "cloudflare", "express", "asp.net"):
        if marker in server or marker in powered_by:
            technologies.append(marker)

    return sorted(set(technologies))

