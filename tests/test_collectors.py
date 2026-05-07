import unittest

from routehawk.collectors.html_assets import extract_javascript_assets
from routehawk.collectors.openapi import endpoints_from_openapi
from routehawk.collectors.robots import parse_robots_txt
from routehawk.collectors.security_txt import parse_security_txt
from routehawk.collectors.sitemap import parse_sitemap_xml
from routehawk.core.scope import ScopeValidator


class CollectorTests(unittest.TestCase):
    def test_extracts_scoped_javascript_assets(self):
        html = """
        <script src="/static/main.js"></script>
        <script src="https://cdn.evil.com/app.js"></script>
        <link rel="modulepreload" href="/static/chunk.js">
        """
        scope = ScopeValidator(["example.com", "*.example.com"])
        assets = extract_javascript_assets("https://app.example.com", html, scope)
        self.assertEqual(
            assets,
            [
                "https://app.example.com/static/chunk.js",
                "https://app.example.com/static/main.js",
            ],
        )

    def test_parses_robots_paths(self):
        text = """
        User-agent: *
        Disallow: /admin
        Allow: /api/public
        Sitemap: https://example.com/sitemap.xml
        """
        self.assertEqual(
            parse_robots_txt(text),
            ["/admin", "/api/public", "https://example.com/sitemap.xml"],
        )

    def test_parses_sitemap_urls(self):
        text = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/api/users/1</loc></url>
        </urlset>
        """
        self.assertEqual(parse_sitemap_xml(text), ["https://example.com/api/users/1"])

    def test_openapi_endpoints_are_scored_and_tagged(self):
        spec = {
            "paths": {
                "/api/users/{id}/billing": {
                    "get": {"tags": ["billing"]},
                    "post": {},
                }
            }
        }
        endpoints = endpoints_from_openapi(spec, "https://example.com/openapi.json")
        self.assertEqual(len(endpoints), 2)
        self.assertEqual(endpoints[0].normalized_path, "/api/users/{id}/billing")
        self.assertIn("object-reference", endpoints[0].tags)
        self.assertGreaterEqual(endpoints[0].risk_score, 75)

    def test_parses_security_txt_fields(self):
        text = """
        Contact: mailto:security@example.test
        Contact: https://example.test/security
        Policy: https://example.test/policy
        """
        fields = parse_security_txt(text)
        self.assertEqual(len(fields["contact"]), 2)
        self.assertEqual(fields["policy"], ["https://example.test/policy"])


if __name__ == "__main__":
    unittest.main()
