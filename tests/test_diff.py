import unittest

from routehawk.core.diff import build_endpoint_diff, endpoint_key


class EndpointDiffTests(unittest.TestCase):
    def test_endpoint_key_prefers_normalized_path(self):
        endpoint = {
            "method": "get",
            "raw_path": "/api/users/123",
            "normalized_path": "/api/users/{id}",
        }

        self.assertEqual(endpoint_key(endpoint), "GET /api/users/{id}")

    def test_diff_reports_new_endpoint(self):
        previous = {
            "endpoints": [
                {
                    "method": "GET",
                    "normalized_path": "/api/users/{id}",
                    "risk_score": 60,
                    "tags": ["object-reference"],
                    "sources": ["javascript"],
                }
            ]
        }
        current = {
            "endpoints": [
                {
                    "method": "GET",
                    "normalized_path": "/api/users/{id}",
                    "risk_score": 60,
                    "tags": ["object-reference"],
                    "sources": ["javascript"],
                },
                {
                    "method": "GET",
                    "normalized_path": "/api/admin/export",
                    "risk_score": 85,
                    "tags": ["admin", "data-export"],
                    "sources": ["openapi"],
                },
            ]
        }

        diff = build_endpoint_diff(previous, current)

        self.assertEqual(diff["new_count"], 1)
        self.assertEqual(diff["removed_count"], 0)
        self.assertEqual(diff["unchanged_count"], 1)
        self.assertEqual(diff["new"][0]["endpoint"], "GET /api/admin/export")
        self.assertEqual(diff["new"][0]["risk_score"], 85)

    def test_diff_reports_removed_and_changed_endpoints(self):
        previous = {
            "endpoints": [
                {"method": "GET", "normalized_path": "/api/users/{id}", "risk_score": 55},
                {"method": "GET", "normalized_path": "/debug/config", "risk_score": 35},
            ]
        }
        current = {
            "endpoints": [
                {"method": "GET", "normalized_path": "/api/users/{id}", "risk_score": 80},
            ]
        }

        diff = build_endpoint_diff(previous, current)

        self.assertEqual(diff["removed_count"], 1)
        self.assertEqual(diff["changed_count"], 1)
        self.assertEqual(diff["unchanged_count"], 0)
        self.assertEqual(diff["removed"][0]["endpoint"], "GET /debug/config")
        self.assertEqual(diff["changed"][0]["previous_risk_score"], 55)
        self.assertEqual(diff["changed"][0]["current_risk_score"], 80)


if __name__ == "__main__":
    unittest.main()
