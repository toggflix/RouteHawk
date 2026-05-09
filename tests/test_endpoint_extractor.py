import unittest

from routehawk.analyzers.endpoint_extractor import extract_endpoints, unique_paths
from routehawk.core.models import SuppressionConfig


class EndpointExtractorTests(unittest.TestCase):
    def test_extracts_relative_and_absolute_api_paths(self):
        text = """
        fetch("/api/users/123/billing")
        const url = "https://api.example.com/v1/orders/1001";
        """
        endpoints = extract_endpoints(text)
        paths = unique_paths(endpoints)
        self.assertIn("/api/users/123/billing", paths)
        self.assertIn("/v1/orders/1001", paths)
        order = [endpoint for endpoint in endpoints if endpoint.path == "/v1/orders/1001"]
        self.assertTrue(order)
        self.assertEqual(order[0].confidence, "medium")

    def test_extracts_method_prefixed_routes(self):
        endpoints = extract_endpoints("POST /api/admin/users/1/role")
        self.assertEqual(endpoints[0].method, "POST")
        self.assertEqual(endpoints[0].path, "/api/admin/users/1/role")
        self.assertEqual(endpoints[0].confidence, "high")

    def test_rejects_javascript_expression_false_positives(self):
        text = """
        "/{id}?e={value}&f.isInteger(c.pick)?c={value}"
        "/{id}?.5*jQuery.easing.easeInBounce(a,2*b,0,d,e)"
        "/foo(bar)"
        "/api/users/1 + something"
        """
        paths = unique_paths(extract_endpoints(text))
        self.assertNotIn("/{id}?e={value}&f.isInteger(c.pick)?c={value}", paths)
        self.assertNotIn("/{id}?.5*jQuery.easing.easeInBounce(a,2*b,0,d,e)", paths)
        self.assertNotIn("/foo(bar)", paths)
        self.assertNotIn("/api/users/1 + something", paths)
        self.assertNotIn("/api/users/1", paths)

    def test_keeps_valid_api_paths_and_queries(self):
        text = """
        "/api/users/123/billing"
        "/questions/123/abcdef"
        "/api/users?id=123&tab=billing"
        "/search?q=test"
        "/graphql"
        "/api/report.json"
        "/swagger.json"
        """
        paths = unique_paths(extract_endpoints(text))
        self.assertIn("/api/users/123/billing", paths)
        self.assertIn("/questions/123/abcdef", paths)
        self.assertIn("/api/users?id=123&tab=billing", paths)
        self.assertIn("/search?q=test", paths)
        self.assertIn("/graphql", paths)
        self.assertIn("/api/report.json", paths)
        self.assertIn("/swagger.json", paths)

    def test_rejects_third_party_documentation_and_vendor_noise(self):
        text = """
        "/TR/{id}/REC-css3-selectors-20110929/"
        "/TR/{id}/WD-DOM-Level-3-Events-20030331/ecma-script-binding.html"
        "/Microsoft/TypeScript/issues/{id}"
        "/twbs/bootstrap"
        "/krzysu/flot.tooltip"
        "/Studio-42/elFinder/pull/{id}"
        "/Consortium/Legal/{id}/copyright-software-and-document"
        "/youtubei/v1/live_chat/{token}"
        "/XML/{id}/namespace"
        "/get/videoqualityreport/?v={value}"
        "/C)/{id}"
        "/e)/{id}"
        """

        paths = unique_paths(extract_endpoints(text))

        self.assertEqual(paths, [])

    def test_keeps_application_routes_after_noise_suppression(self):
        text = """
        "/api/users/{id}/billing"
        "/api/orders/{id}"
        "/questions/{id}/{token}"
        "/blog/{id}/{token}"
        "/graphql"
        "/openapi.json"
        "/swagger.json"
        "/payment/{id}"
        "/auth/callback"
        "/login"
        "/account/settings"
        "/api/v1/products/{id}"
        """

        paths = unique_paths(extract_endpoints(text))

        self.assertIn("/api/users/{id}/billing", paths)
        self.assertIn("/api/orders/{id}", paths)
        self.assertIn("/questions/{id}/{token}", paths)
        self.assertIn("/blog/{id}/{token}", paths)
        self.assertIn("/graphql", paths)
        self.assertIn("/openapi.json", paths)
        self.assertIn("/swagger.json", paths)
        self.assertIn("/payment/{id}", paths)
        self.assertIn("/auth/callback", paths)
        self.assertIn("/login", paths)
        self.assertIn("/account/settings", paths)
        self.assertIn("/api/v1/products/{id}", paths)

    def test_sets_medium_confidence_for_clean_non_method_paths(self):
        endpoints = extract_endpoints('"/api/users/123/billing"')
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].confidence, "medium")

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
