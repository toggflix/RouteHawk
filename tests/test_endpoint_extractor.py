import unittest

from routehawk.analyzers.endpoint_extractor import extract_endpoints, unique_paths
from routehawk.core.models import SuppressionConfig


class EndpointExtractorTests(unittest.TestCase):
    def test_extracts_relative_and_absolute_api_paths(self):
        text = """
        fetch("/api/users/123/billing")
        const url = "https://api.example.com/v1/orders/1001";
        """
        paths = unique_paths(extract_endpoints(text))
        self.assertIn("/api/users/123/billing", paths)
        self.assertIn("/v1/orders/1001", paths)

    def test_extracts_method_prefixed_routes(self):
        endpoints = extract_endpoints("POST /api/admin/users/1/role")
        self.assertEqual(endpoints[0].method, "POST")
        self.assertEqual(endpoints[0].path, "/api/admin/users/1/role")

    def test_ignores_html_closing_tags(self):
        paths = unique_paths(extract_endpoints("<html><body></body></html>"))
        self.assertEqual(paths, [])

    def test_suppresses_static_asset_false_positives(self):
        text = """
        "/favicon.ico?v=123"
        "/static/css/app.css"
        "/images/logo.png?cache=1"
        "//cdn.example.com/library"
        "/api/report.json"
        "/swagger.json"
        "/graphql"
        """

        paths = unique_paths(extract_endpoints(text))

        self.assertNotIn("/favicon.ico?v=123", paths)
        self.assertNotIn("/static/css/app.css", paths)
        self.assertNotIn("/images/logo.png?cache=1", paths)
        self.assertNotIn("//cdn.example.com/library", paths)
        self.assertIn("/api/report.json", paths)
        self.assertIn("/swagger.json", paths)
        self.assertIn("/graphql", paths)

    def test_supports_configurable_suppression_rules(self):
        suppression = SuppressionConfig(
            ignore_suffixes=[".bak"],
            ignore_path_prefixes=["/noise/"],
            ignore_regexes=[r"/api/internal/cache/\d+"],
        )
        text = """
        "/download/archive.bak"
        "/noise/telemetry"
        "/api/internal/cache/123"
        "/api/users/123/billing"
        """

        paths = unique_paths(extract_endpoints(text, suppression))

        self.assertNotIn("/download/archive.bak", paths)
        self.assertNotIn("/noise/telemetry", paths)
        self.assertNotIn("/api/internal/cache/123", paths)
        self.assertIn("/api/users/123/billing", paths)


if __name__ == "__main__":
    unittest.main()
