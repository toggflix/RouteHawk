from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List
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
    summary = extract_javascript_asset_summary(base_url, html, scope)
    return summary["allowed_urls"]


def extract_javascript_asset_summary(base_url: str, html: str, scope: ScopeValidator) -> Dict[str, object]:
    parser = _JavaScriptAssetParser(base_url)
    parser.feed(html)
    discovered = sorted(parser.urls)
    allowed = []
    skipped = 0
    for url in discovered:
        if scope.is_url_allowed(url):
            allowed.append(url)
        else:
            skipped += 1
    return {
        "allowed_urls": allowed,
        "discovered": len(discovered),
        "skipped_out_of_scope": skipped,
    }
