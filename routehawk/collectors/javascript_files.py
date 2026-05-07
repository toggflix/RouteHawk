from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from routehawk.core.http_client import ScopeSafeHttpClient


@dataclass(frozen=True)
class CachedJavaScript:
    url: str
    sha256: str
    path: Path
    size: int


async def download_javascript(
    client: ScopeSafeHttpClient,
    url: str,
    cache_dir: Path,
    max_bytes: int = 2_000_000,
) -> CachedJavaScript:
    response = await client.get_text(url)
    content = response.text.encode("utf-8", errors="ignore")
    if len(content) > max_bytes:
        content = content[:max_bytes]

    digest = hashlib.sha256(content).hexdigest()
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{digest}.js"
    if not path.exists():
        path.write_bytes(content)

    return CachedJavaScript(url=url, sha256=digest, path=path, size=len(content))

