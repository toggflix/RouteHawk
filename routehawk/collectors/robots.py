from __future__ import annotations

from typing import List


def parse_robots_txt(text: str) -> List[str]:
    paths = []
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in {"allow", "disallow", "sitemap"}:
            candidate = value.strip()
            if candidate:
                paths.append(candidate)
    return sorted(set(paths))

