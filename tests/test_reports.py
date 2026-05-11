import unittest

from routehawk.cli import _dedupe_endpoints, _findings_from_endpoints
from routehawk.collectors.openapi import endpoints_from_openapi
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
                extraction_confidence="medium",
                app_relevance="high",
                relevance_reasons=["First-party API-like path"],
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
                extraction_confidence="high",
                app_relevance="high",
                relevance_reasons=["Structured OpenAPI evidence"],
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
        self.assertEqual(merged[0].extraction_confidence, "high")
        self.assertEqual(merged[0].app_relevance, "high")
        self.assertIn("Structured OpenAPI evidence", merged[0].relevance_reasons)
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
            app_relevance="high",
            relevance_reasons=["First-party API-like path"],
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
            app_relevance="high",
            relevance_reasons=["First-party API-like path"],
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
        self.assertIn("Extraction confidence:", markdown)
        self.assertIn("App relevance:", markdown)
        self.assertIn("First-party API-like path", markdown)
        self.assertIn("Risk reasons:", markdown)
        self.assertIn("Risk Signals", html)
        self.assertIn("Extraction Confidence", html)
        self.assertIn("App Relevance", html)
        self.assertIn("First-party API-like path", html)
        self.assertIn("Relevance: high", html)
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
            source_coverage={
                "homepage": {"fetched": True, "status": 200},
                "javascript": {"discovered": 2, "downloaded": 0, "skipped_out_of_scope": 2, "failed": 0},
                "robots": {"checked": True, "status": 200},
                "sitemap": {"checked": True, "status": 200},
                "security_txt": {"checked": True, "status": 200},
                "openapi": {"checked": True, "candidates_checked": 6, "found": 0},
                "graphql": {"checked": True, "candidates_checked": 3, "found": 0},
                "auth_behavior": {"enabled": False, "probe_limit": 0},
            },
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
        self.assertIn("Scan Explanation", markdown)
        self.assertNotIn("No JavaScript assets were discovered on the fetched page.", markdown)
        self.assertIn("JavaScript assets were discovered, but none were downloaded.", markdown)
        self.assertIn("Skipped `2` JavaScript assets because they were outside configured scope.", markdown)
        self.assertIn("Auth behavior checks were disabled.", markdown)
        self.assertIn("JavaScript Files", html)
        self.assertIn("Metadata", html)
        self.assertIn("Source Coverage", html)
        self.assertIn("Scan Explanation", html)
        self.assertIn("JavaScript assets were discovered, but none were downloaded.", html)
        self.assertIn("Skipped 2 JavaScript assets because they were outside configured scope.", html)
        self.assertIn("Auth behavior checks were disabled.", html)

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

    def test_openapi_collector_marks_endpoints_high_extraction_confidence(self):
        spec = {
            "paths": {
                "/api/users/{id}/billing": {
                    "get": {},
                }
            }
        }
        endpoints = endpoints_from_openapi(spec, "https://example.com/swagger.json")
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].extraction_confidence, "high")

    def test_endpoint_model_uses_default_extraction_confidence_for_backward_compat(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="https://example.com/main.js",
            method="GET",
            raw_path="/api/users/1/billing",
            normalized_path="/api/users/{id}/billing",
        )
        self.assertEqual(endpoint.extraction_confidence, "medium")

    def test_endpoint_model_uses_default_app_relevance_for_backward_compat(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="https://example.com/main.js",
            method="GET",
            raw_path="/api/users/1/billing",
            normalized_path="/api/users/{id}/billing",
        )
        self.assertEqual(endpoint.app_relevance, "medium")
        self.assertEqual(endpoint.relevance_reasons, [])


if __name__ == "__main__":
    unittest.main()
