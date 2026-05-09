import unittest

from routehawk.cli import _apply_safe_profile, build_parser
from routehawk.core.models import RulesConfig, ScanOptions


class CliTests(unittest.TestCase):
    def test_parser_accepts_bug_bounty_safe_profile(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "scan",
                "--target",
                "https://app.example.com",
                "--scope",
                "example.com",
                "--safe-profile",
                "bug-bounty",
            ]
        )

        self.assertEqual(args.command, "scan")
        self.assertEqual(args.safe_profile, "bug-bounty")

    def test_safe_profile_applies_low_impact_overrides(self):
        rules = RulesConfig(
            max_rps_per_host=8,
            max_concurrency=40,
            max_retries=4,
            retry_backoff_seconds=0.25,
            respect_retry_after=False,
            request_budget_per_scan=2000,
        )
        options = ScanOptions(
            check_auth_behavior=True,
            auth_probe_limit=30,
        )

        effective_rules, effective_options = _apply_safe_profile(rules, options, "bug-bounty")

        self.assertEqual(effective_rules.max_rps_per_host, 1)
        self.assertEqual(effective_rules.max_concurrency, 2)
        self.assertEqual(effective_rules.max_retries, 1)
        self.assertAlmostEqual(effective_rules.retry_backoff_seconds, 1.0)
        self.assertTrue(effective_rules.respect_retry_after)
        self.assertEqual(effective_rules.request_budget_per_scan, 500)
        self.assertFalse(effective_options.check_auth_behavior)
        self.assertEqual(effective_options.auth_probe_limit, 0)

    def test_routehawk_help_still_works(self):
        parser = build_parser()
        text = parser.format_help()
        self.assertIn("authorized, low-impact reconnaissance", text)
        self.assertIn("scan", text)


if __name__ == "__main__":
    unittest.main()
