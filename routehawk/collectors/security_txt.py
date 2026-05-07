from __future__ import annotations

from typing import Dict, List


def parse_security_txt(text: str) -> Dict[str, List[str]]:
    fields: Dict[str, List[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields

