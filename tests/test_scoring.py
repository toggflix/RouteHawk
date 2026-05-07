import unittest

from routehawk.analyzers.idor_candidates import score_endpoint, severity_for_score
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


if __name__ == "__main__":
    unittest.main()
