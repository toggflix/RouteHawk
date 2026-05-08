import unittest

from routehawk.analyzers.idor_candidates import (
    endpoint_confidence,
    score_endpoint,
    score_endpoint_with_reasons,
    severity_for_score,
)
from routehawk.analyzers.route_classifier import classify_endpoint


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


if __name__ == "__main__":
    unittest.main()
