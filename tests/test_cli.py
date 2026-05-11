import unittest

import routehawk.cli as cli_module
from routehawk.cli import _apply_safe_profile, _run_scan, build_parser
from routehawk.core.http_client import RequestBudgetExceeded
from routehawk.core.models import RulesConfig, ScanOptions
from routehawk.core.scope import ScopeValidator


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


class _BudgetStopClient:
    def __init__(self, scope, rules):
        self.scope = scope
        self.rules = rules

    async def get_text(self, url):
        raise RequestBudgetExceeded("Request budget exceeded for this scan")

    async def aclose(self):
        return None


class CliBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_budget_exceeded_scan_returns_controlled_warning(self):
        original_client = cli_module.ScopeSafeHttpClient
        cli_module.ScopeSafeHttpClient = _BudgetStopClient
        try:
            validator = ScopeValidator(["example.com"])
            result = await _run_scan(
                "https://example.com",
                ["example.com"],
                validator,
                config=None,
                safe_profile="bug-bounty",
            )
        finally:
            cli_module.ScopeSafeHttpClient = original_client

        self.assertEqual(result.target, "https://example.com")
        self.assertIn("Request budget exceeded; scan stopped early.", result.warnings)
        self.assertEqual(len([w for w in result.warnings if "Request budget exceeded" in w]), 1)

    async def test_run_scan_carries_scope_normalization_and_fingerprints(self):
        original_client = cli_module.ScopeSafeHttpClient
        cli_module.ScopeSafeHttpClient = _BudgetStopClient
        try:
            validator = ScopeValidator(["www.whatnot.com"])
            result = await _run_scan(
                "https://www.whatnot.com/path?x=1",
                ["www.whatnot.com"],
                validator,
                config=None,
                safe_profile="bug-bounty",
                scope_normalization_notes=[
                    "Normalized scope entry: https://www.whatnot.com -> www.whatnot.com"
                ],
            )
        finally:
            cli_module.ScopeSafeHttpClient = original_client

        self.assertEqual(result.target_fingerprint, "https://www.whatnot.com")
        self.assertEqual(result.scope_fingerprint, "www.whatnot.com")
        self.assertIn(
            "Normalized scope entry: https://www.whatnot.com -> www.whatnot.com",
            result.warnings,
        )


if __name__ == "__main__":
    unittest.main()
