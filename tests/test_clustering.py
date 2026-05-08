import unittest

from routehawk.analyzers.clustering import cluster_endpoints_by_prefix
from routehawk.core.models import Endpoint, ScanResult
from routehawk.reports.html import render_html
from routehawk.reports.markdown import render_markdown
from routehawk.reports.summary import build_summary


class ClusteringTests(unittest.TestCase):
    def test_clusters_endpoints_by_route_prefix(self):
        endpoints = [
            Endpoint(
                source="javascript",
                source_url="main.js",
                method="GET",
                raw_path="/api/users/1/billing",
                normalized_path="/api/users/{id}/billing",
                tags=["billing"],
                risk_score=80,
            ),
            Endpoint(
                source="openapi",
                source_url="swagger.json",
                method="POST",
                raw_path="/api/users/{id}/role",
                normalized_path="/api/users/{id}/role",
                tags=["authorization"],
                risk_score=90,
            ),
        ]

        groups = cluster_endpoints_by_prefix(endpoints)

        self.assertEqual(groups[0].prefix, "/api/users")
        self.assertEqual(groups[0].count, 2)
        self.assertEqual(groups[0].max_risk_score, 90)
        self.assertEqual(groups[0].methods, ["GET", "POST"])

    def test_reports_include_route_groups(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="main.js",
            method="GET",
            raw_path="/api/users/1/billing",
            normalized_path="/api/users/{id}/billing",
            tags=["billing"],
            risk_score=80,
        )
        result = ScanResult(target="https://example.com", scope=["example.com"], endpoints=[endpoint])

        summary = build_summary(result)
        markdown = render_markdown(result)
        html = render_html(result)

        self.assertEqual(summary.route_groups[0].prefix, "/api/users")
        self.assertIn("Route Groups", markdown)
        self.assertIn("Route Groups", html)
        self.assertIn("/api/users", html)


if __name__ == "__main__":
    unittest.main()
