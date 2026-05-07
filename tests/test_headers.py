import unittest

from routehawk.analyzers.cors import analyze_cors_headers
from routehawk.analyzers.security_headers import missing_security_headers
from routehawk.analyzers.auth_behavior import classify_status_code
from routehawk.cli import _header_metadata


class HeaderAnalysisTests(unittest.TestCase):
    def test_reports_missing_security_headers(self):
        missing = missing_security_headers({"Content-Security-Policy": "default-src 'self'"})

        self.assertIn("x-frame-options", missing)
        self.assertNotIn("content-security-policy", missing)

    def test_reports_cors_signals(self):
        signals = analyze_cors_headers(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )

        self.assertEqual(signals, ["wildcard-origin-with-credentials"])

    def test_builds_header_metadata_records(self):
        records = _header_metadata(
            "https://example.com",
            200,
            {
                "Access-Control-Allow-Origin": "*",
                "Content-Security-Policy": "default-src 'self'",
            },
        )

        self.assertEqual(records[0].source, "security_headers")
        self.assertEqual(records[1].source, "cors")
        self.assertIn("missing", records[0].details)
        self.assertEqual(records[1].details["signals"], ["cors-enabled"])

    def test_classifies_auth_behavior_status_codes(self):
        self.assertEqual(classify_status_code(401), "auth-required")
        self.assertEqual(classify_status_code(403), "forbidden")
        self.assertEqual(classify_status_code(405), "method-exists-maybe")


if __name__ == "__main__":
    unittest.main()
