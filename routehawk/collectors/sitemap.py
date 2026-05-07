from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List


def parse_sitemap_xml(text: str) -> List[str]:
    root = ET.fromstring(text)
    urls = []
    for element in root.iter():
        if element.tag.endswith("loc") and element.text:
            urls.append(element.text.strip())
    return sorted(set(urls))

