from __future__ import annotations

import re
from urllib.parse import urlparse

from routehawk.core.http_client import ScopeSafeHttpClient
from routehawk.core.models import Asset


TITLE_RE = re.compile(r"<title[^>]*>(?P<title>.*?)</title>", re.I | re.S)


async def check_live_host(client: ScopeSafeHttpClient, url: str) -> Asset:
    response = await client.get_text(url)
    parsed = urlparse(response.url)
    title = _extract_title(response.text)
    return Asset(
        host=parsed.hostname or "",
        scheme=parsed.scheme,
        status=response.status_code,
        title=title,
    )


def _extract_title(html: str) -> str:
    match = TITLE_RE.search(html)
    if not match:
        return ""
    return " ".join(match.group("title").split())

