import unittest

from routehawk.cli import _dedupe_endpoints, _findings_from_endpoints
from routehawk.core.models import Endpoint, JavaScriptFile, MetadataRecord, ScanResult
from routehawk.reports.html import render_html
from routehawk.reports.markdown import render_markdown
from routehawk.reports.summary import build_summary


class ReportTests(unittest.TestCase):
    def test_dedupe_merges_endpoint_evidence(self):
        endpoints = [
            Endpoint(
                source="javascript",
                source_url="https://example.com/main.js",
                method="GET",
                raw_path="/api/users/1/billing",
                normalized_path="/api/users/{id}/billing",
                tags=["object-reference", "billing"],
                risk_score=80,
                sources=["javascript"],
                source_urls=["https://example.com/main.js"],
                raw_paths=["/api/users/1/billing"],
            ),
            Endpoint(
                source="openapi",
                source_url="https://example.com/swagger.json",
                method="GET",
                raw_path="/api/users/{id}/billing",
                normalized_path="/api/users/{id}/billing",
                tags=["object-reference", "billing", "user-object"],
                risk_score=85,
                sources=["openapi"],
                source_urls=["https://example.com/swagger.json"],
                raw_paths=["/api/users/{id}/billing"],
            ),
        ]

        merged = _dedupe_endpoints(endpoints)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].risk_score, 85)
        self.assertEqual(merged[0].sources, ["javascript", "openapi"])
        self.assertEqual(merged[0].confidence, "high")
        self.assertIn("Corroborated by 2 source URLs", merged[0].evidence)
        self.assertIn("Endpoint found in javascript", merged[0].evidence)
        self.assertIn("Endpoint found in openapi", merged[0].evidence)
        self.assertTrue(any(item.startswith("Risk signal:") for item in merged[0].evidence))

    def test_summary_counts_sources_tags_and_risk(self):
        endpoint = Endpoint(
            source="openapi",
            source_url="https://example.com/swagger.json",
            method="GET",
            raw_path="/api/users/{id}/billing",
            normalized_path="/api/users/{id}/billing",
            tags=["object-reference", "billing", "user-object"],
            risk_score=85,
            sources=["javascript", "openapi"],
            source_urls=["https://example.com/main.js", "https://example.com/swagger.json"],
            raw_paths=["/api/users/1/billing", "/api/users/{id}/billing"],
        )
        result = ScanResult(target="https://example.com", scope=["example.com"], endpoints=[endpoint])

        summary = build_summary(result)

        self.assertEqual(summary.endpoint_count, 1)
        self.assertEqual(summary.javascript_file_count, 0)
        self.assertEqual(summary.metadata_count, 0)
        self.assertEqual(summary.high_risk_count, 1)
        self.assertEqual(summary.source_counts["javascript"], 1)
        self.assertEqual(summary.source_counts["openapi"], 1)
        self.assertEqual(summary.tag_counts["billing"], 1)

    def test_reports_include_manual_candidates_and_inventory(self):
        endpoint = Endpoint(
            source="openapi",
            source_url="https://example.com/swagger.json",
            method="GET",
            raw_path="/api/users/{id}/billing",
            normalized_path="/api/users/{id}/billing",
            tags=["object-reference", "billing", "user-object"],
            risk_score=85,
            sources=["openapi"],
            source_urls=["https://example.com/swagger.json"],
            raw_paths=["/api/users/{id}/billing"],
            evidence=["Endpoint found in openapi", "Billing or payment related path"],
        )
        findings = _findings_from_endpoints("https://example.com", [endpoint])
        result = ScanResult(
            target="https://example.com",
            scope=["example.com"],
            endpoints=[endpoint],
            findings=findings,
        )

        markdown = render_markdown(result)
        html = render_html(result)

        self.assertIn("Top Manual Test Candidates", markdown)
        self.assertIn("GET `/api/users/{id}/billing`", markdown)
        self.assertIn("Manual Test Plan", html)
        self.assertIn("/api/users/{id}/billing", html)
        self.assertIn("filter-search", html)
        self.assertIn("filter-status", html)
        self.assertIn("Endpoint confidence:", markdown)
        self.assertIn("Risk reasons:", markdown)
        self.assertIn("Risk Signals", html)
        self.assertIn("data-copy-checklist", html)
        self.assertIn("data-copy-draft", html)
        self.assertIn("Copy finding draft", html)
        self.assertIn('data-triage="interesting"', html)
        self.assertIn("routehawk:triage", html)
        self.assertIn('data-report-item="finding"', html)
        self.assertIn('data-report-item="endpoint"', html)

    def test_reports_include_javascript_and_metadata_sections(self):
        result = ScanResult(
            target="https://example.com",
            scope=["example.com"],
            javascript_files=[
                JavaScriptFile(
                    url="https://example.com/main.js",
                    sha256="a" * 64,
                    cache_path=".cache/javascript/a.js",
                    size=1234,
                    endpoints_found=7,
                )
            ],
            metadata=[
                MetadataRecord(
                    source="security.txt",
                    url="https://example.com/.well-known/security.txt",
                    status=200,
                    details={"contact_count": 1},
                )
            ],
        )

        markdown = render_markdown(result)
        html = render_html(result)

        self.assertIn("JavaScript Files", markdown)
        self.assertIn("security.txt", markdown)
        self.assertIn("JavaScript Files", html)
        self.assertIn("Metadata", html)

    def test_graphql_candidate_uses_graphql_checklist(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="https://example.com/main.js",
            method="GET",
            raw_path="/graphql",
            normalized_path="/graphql",
            tags=["graphql"],
            risk_score=45,
            sources=["javascript"],
            source_urls=["https://example.com/main.js"],
            raw_paths=["/graphql"],
            evidence=["Endpoint found in javascript", "GraphQL route keyword"],
        )

        findings = _findings_from_endpoints("https://example.com", [endpoint])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "graphql_candidate")
        self.assertIn("GraphQL-shaped requests", " ".join(findings[0].manual_check))


if __name__ == "__main__":
    unittest.main()
