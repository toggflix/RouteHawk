from __future__ import annotations

from html.parser import HTMLParser
from typing import List
from urllib.parse import urljoin

from routehawk.core.scope import ScopeValidator


class _JavaScriptAssetParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.urls = set()

    def handle_starttag(self, tag: str, attrs: list) -> None:
        values = {key.lower(): value for key, value in attrs if value}
        if tag.lower() == "script" and values.get("src"):
            self.urls.add(urljoin(self.base_url, values["src"]))
            return

        if tag.lower() != "link" or not values.get("href"):
            return

        rel = {item.lower() for item in values.get("rel", "").split()}
        if rel.intersection({"preload", "modulepreload"}):
            candidate = urljoin(self.base_url, values["href"])
            if candidate.lower().split("?", 1)[0].endswith(".js"):
                self.urls.add(candidate)


def extract_javascript_assets(base_url: str, html: str, scope: ScopeValidator) -> List[str]:
    parser = _JavaScriptAssetParser(base_url)
    parser.feed(html)
    return sorted(url for url in parser.urls if scope.is_url_allowed(url))
