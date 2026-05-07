from __future__ import annotations

from typing import Dict, List


EXPECTED_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


def missing_security_headers(headers: Dict[str, str]) -> List[str]:
    lowered = {key.lower() for key in headers}
    return [header for header in EXPECTED_HEADERS if header not in lowered]

