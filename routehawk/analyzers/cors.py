from __future__ import annotations

from typing import Dict, List


def analyze_cors_headers(headers: Dict[str, str]) -> List[str]:
    lowered = {key.lower(): value for key, value in headers.items()}
    findings = []
    origin = lowered.get("access-control-allow-origin")
    credentials = lowered.get("access-control-allow-credentials")
    if origin == "*" and credentials == "true":
        findings.append("wildcard-origin-with-credentials")
    elif origin:
        findings.append("cors-enabled")
    return findings

