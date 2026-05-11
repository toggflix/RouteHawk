import unittest

from routehawk.core.diff import (
    build_endpoint_diff,
    endpoint_key,
    scope_fingerprint,
    target_fingerprint,
)


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
        self.assertEqual(diff["new"][0]["extraction_confidence"], "medium")

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
        self.assertEqual(diff["changed"][0]["changed_fields"], ["risk_score"])
        self.assertEqual(diff["changed"][0]["deltas"]["risk_score"]["previous"], 55)
        self.assertEqual(diff["changed"][0]["deltas"]["risk_score"]["current"], 80)

    def test_diff_reports_confidence_tag_source_changes(self):
        previous = {
            "endpoints": [
                {
                    "method": "POST",
                    "normalized_path": "/api/users/{id}/role",
                    "risk_score": 70,
                    "extraction_confidence": "medium",
                    "tags": ["authorization"],
                    "sources": ["javascript"],
                    "risk_reasons": ["object identifier detected"],
                    "source_urls": ["https://example.com/main.js"],
                }
            ]
        }
        current = {
            "endpoints": [
                {
                    "method": "POST",
                    "normalized_path": "/api/users/{id}/role",
                    "risk_score": 70,
                    "extraction_confidence": "high",
                    "tags": ["admin", "authorization"],
                    "sources": ["javascript", "openapi"],
                    "risk_reasons": ["object identifier detected", "admin keyword"],
                    "source_urls": [
                        "https://example.com/main.js",
                        "https://example.com/openapi.json",
                    ],
                }
            ]
        }

        diff = build_endpoint_diff(previous, current)

        self.assertEqual(diff["new_count"], 0)
        self.assertEqual(diff["removed_count"], 0)
        self.assertEqual(diff["changed_count"], 1)
        self.assertEqual(diff["unchanged_count"], 0)
        changed = diff["changed"][0]
        self.assertIn("extraction_confidence", changed["changed_fields"])
        self.assertIn("tags", changed["changed_fields"])
        self.assertIn("sources", changed["changed_fields"])
        self.assertEqual(changed["deltas"]["extraction_confidence"]["previous"], "medium")
        self.assertEqual(changed["deltas"]["extraction_confidence"]["current"], "high")
        self.assertEqual(changed["deltas"]["tags"]["added"], ["admin"])
        self.assertEqual(changed["deltas"]["tags"]["removed"], [])
        self.assertEqual(changed["deltas"]["sources"]["added"], ["openapi"])
        self.assertEqual(changed["deltas"]["sources"]["removed"], [])
        self.assertIn("risk_reasons", changed["deltas"])
        self.assertIn("source_urls", changed["deltas"])
        self.assertEqual(changed["current"]["source_urls_count"], 2)
        self.assertEqual(changed["current"]["risk_reason_count"], 2)

    def test_diff_ignores_unchanged_endpoint(self):
        payload = {
            "endpoints": [
                {
                    "method": "GET",
                    "normalized_path": "/graphql",
                    "risk_score": 10,
                    "tags": ["graphql"],
                    "sources": ["graphql"],
                    "extraction_confidence": "high",
                }
            ]
        }

        diff = build_endpoint_diff(payload, payload)

        self.assertEqual(diff["new_count"], 0)
        self.assertEqual(diff["removed_count"], 0)
        self.assertEqual(diff["changed_count"], 0)
        self.assertEqual(diff["unchanged_count"], 1)
        self.assertEqual(diff["changed"], [])

    def test_diff_marks_target_and_scope_changes(self):
        previous = {
            "target": "https://app.example.com",
            "scope": ["example.com"],
            "target_fingerprint": target_fingerprint("https://app.example.com"),
            "scope_fingerprint": scope_fingerprint(["example.com"]),
            "endpoints": [],
        }
        current = {
            "target": "https://api.example.com",
            "scope": ["api.example.com"],
            "target_fingerprint": target_fingerprint("https://api.example.com"),
            "scope_fingerprint": scope_fingerprint(["api.example.com"]),
            "endpoints": [],
        }

        diff = build_endpoint_diff(previous, current)

        self.assertTrue(diff["target_changed"])
        self.assertTrue(diff["scope_changed"])
        self.assertIn("different target or scope fingerprints", diff["warning"])

    def test_diff_scope_fingerprint_is_order_stable(self):
        first = scope_fingerprint(["api.example.com", "example.com"])
        second = scope_fingerprint(["example.com", "api.example.com"])
        self.assertEqual(first, second)

    def test_diff_keeps_same_target_scope_without_warning(self):
        previous = {
            "target": "https://app.example.com",
            "scope": ["example.com", "*.example.com"],
            "target_fingerprint": target_fingerprint("https://app.example.com"),
            "scope_fingerprint": scope_fingerprint(["example.com", "*.example.com"]),
            "endpoints": [],
        }
        current = {
            "target": "https://app.example.com/any/path",
            "scope": ["*.example.com", "example.com"],
            "target_fingerprint": target_fingerprint("https://app.example.com"),
            "scope_fingerprint": scope_fingerprint(["*.example.com", "example.com"]),
            "endpoints": [],
        }

        diff = build_endpoint_diff(previous, current)

        self.assertFalse(diff["target_changed"])
        self.assertFalse(diff["scope_changed"])
        self.assertEqual(diff["warning"], "")


if __name__ == "__main__":
    unittest.main()
