import unittest

from routehawk.analyzers.idor_candidates import (
    classify_app_relevance,
    endpoint_confidence,
    score_endpoint,
    score_endpoint_with_reasons,
    severity_for_score,
)
from routehawk.analyzers.route_classifier import classify_endpoint
from routehawk.cli import _should_create_finding
from routehawk.core.models import Endpoint


class ScoringTests(unittest.TestCase):
    def test_scores_billing_idor_candidate_high(self):
        path = "/api/users/{id}/billing"
        tags = classify_endpoint("GET", path)
        score = score_endpoint("GET", path, tags, source="javascript")
        self.assertGreaterEqual(score, 75)
        self.assertEqual(severity_for_score(score), "high")

    def test_scores_plain_health_endpoint_lower(self):
        path = "/health"
        tags = classify_endpoint("GET", path)
        score = score_endpoint("GET", path, tags)
        self.assertLess(score, 50)

    def test_tags_and_scores_graphql_candidate(self):
        path = "/graphql"
        tags = classify_endpoint("GET", path)
        score = score_endpoint("GET", path, tags, source="javascript")
        self.assertIn("graphql", tags)
        self.assertGreaterEqual(score, 45)

    def test_scoring_returns_reasons(self):
        path = "/api/users/{id}/billing"
        tags = classify_endpoint("GET", path)
        score, reasons = score_endpoint_with_reasons("GET", path, tags, source="openapi")
        self.assertGreaterEqual(score, 75)
        self.assertTrue(reasons)
        self.assertTrue(any("object identifier" in reason for reason in reasons))

    def test_endpoint_confidence_prefers_corroborated_sources(self):
        high = endpoint_confidence(
            sources=["javascript", "openapi"],
            source_url_count=2,
            raw_path_count=2,
            parameter_count=1,
        )
        low = endpoint_confidence(
            sources=["javascript"],
            source_url_count=1,
            raw_path_count=1,
            parameter_count=0,
        )
        self.assertEqual(high, "high")
        self.assertEqual(low, "low")

    def test_classifies_api_billing_path_as_high_app_relevance(self):
        path = "/api/users/{id}/billing"
        tags = classify_endpoint("GET", path)

        relevance, reasons = classify_app_relevance(
            "GET",
            path,
            sources=["javascript"],
            source_urls=["https://example.com/main.js"],
            tags=tags,
        )

        self.assertEqual(relevance, "high")
        self.assertIn("First-party API-like path", reasons)

    def test_blog_and_question_routes_are_not_low_relevance(self):
        for path in ["/questions/{id}/{token}", "/blog/{id}/{token}"]:
            relevance, _ = classify_app_relevance("GET", path, sources=["javascript"], tags=[])
            self.assertIn(relevance, {"medium", "high"})

    def test_classifies_documentation_repository_and_vendor_paths_as_low_relevance(self):
        examples = [
            "/TR/{id}/REC-css3-selectors-20110929/",
            "/XML/{id}/namespace",
            "/Microsoft/TypeScript/issues/{id}",
            "/youtubei/v1/live_chat/{token}",
            "/krzysu/flot.tooltip",
        ]

        for path in examples:
            relevance, reasons = classify_app_relevance("GET", path, sources=["javascript"], tags=[])
            self.assertEqual(relevance, "low")
            self.assertTrue(reasons)

    def test_locale_and_xml_application_routes_are_not_low_relevance(self):
        examples = [
            "/tr/login",
            "/tr/payment/{id}",
            "/xml/export/{id}",
        ]

        for path in examples:
            tags = classify_endpoint("GET", path)
            relevance, _ = classify_app_relevance("GET", path, sources=["javascript"], tags=tags)
            self.assertIn(relevance, {"medium", "high"})

    def test_low_relevance_endpoint_does_not_create_finding(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="https://example.com/main.js",
            method="GET",
            raw_path="/Microsoft/TypeScript/issues/{id}",
            normalized_path="/Microsoft/TypeScript/issues/{id}",
            tags=["object-reference", "admin"],
            app_relevance="low",
            risk_score=90,
        )

        self.assertFalse(_should_create_finding(endpoint))

    def test_high_relevance_risky_endpoint_can_create_finding(self):
        endpoint = Endpoint(
            source="javascript",
            source_url="https://example.com/main.js",
            method="GET",
            raw_path="/api/users/1/billing",
            normalized_path="/api/users/{id}/billing",
            tags=["object-reference", "billing", "user-object"],
            app_relevance="high",
            risk_score=80,
        )

        self.assertTrue(_should_create_finding(endpoint))


if __name__ == "__main__":
    unittest.main()
