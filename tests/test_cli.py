import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import routehawk.cli as cli_module
from routehawk.cli import _apply_safe_profile, _run_scan, build_parser
from routehawk.core.http_client import RequestBudgetExceeded
from routehawk.core.models import RouteHawkConfig, RulesConfig, ScanOptions, ScopeConfig
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


class _FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers=None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _CoverageClient:
    def __init__(self, scope, rules):
        self.scope = scope
        self.rules = rules

    async def get_text(self, url):
        if str(url).rstrip("/") == "https://app.example.com":
            html = """
            <html><head>
            <script src="/static/app.js"></script>
            <script src="https://cdn.other.com/lib.js"></script>
            </head></html>
            """
            return _FakeResponse("https://app.example.com", html, 200, {"server": "demo"})
        if str(url).endswith("/static/app.js"):
            return _FakeResponse("https://app.example.com/static/app.js", 'const route="/api/users/1/billing";', 200)
        raise RuntimeError(f"Unexpected URL: {url}")

    async def aclose(self):
        return None


class _CachedJS:
    def __init__(self, path: Path):
        self.path = path
        self.sha256 = "a" * 64
        self.size = len(path.read_text(encoding="utf-8"))


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

    async def test_source_coverage_tracks_javascript_discovery_download_and_scope_skips(self):
        original_client = cli_module.ScopeSafeHttpClient
        original_download = cli_module.download_javascript
        with TemporaryDirectory() as temporary:
            js_path = Path(temporary) / "app.js"
            js_path.write_text('const route="/api/users/1/billing";', encoding="utf-8")

            async def _fake_download(client, url, cache_root):
                return _CachedJS(js_path)

            cli_module.ScopeSafeHttpClient = _CoverageClient
            cli_module.download_javascript = _fake_download
            try:
                config = RouteHawkConfig(
                    program="test",
                    scope=ScopeConfig(domains=["app.example.com"]),
                    rules=RulesConfig(),
                    scan=ScanOptions(
                        parse_robots=False,
                        parse_sitemap=False,
                        parse_openapi=False,
                        check_common_metadata=False,
                    ),
                    targets=["https://app.example.com"],
                )
                validator = ScopeValidator(["app.example.com"])
                result = await _run_scan(
                    "https://app.example.com",
                    ["app.example.com"],
                    validator,
                    config=config,
                )
            finally:
                cli_module.ScopeSafeHttpClient = original_client
                cli_module.download_javascript = original_download

        coverage = result.source_coverage.get("javascript", {})
        self.assertEqual(coverage.get("discovered"), 2)
        self.assertEqual(coverage.get("downloaded"), 1)
        self.assertEqual(coverage.get("skipped_out_of_scope"), 1)
        self.assertEqual(coverage.get("failed"), 0)
        payload = cli_module._result_to_json(result)
        self.assertIn("source_coverage", payload)
        self.assertEqual(payload["source_coverage"]["javascript"]["downloaded"], 1)

    def test_report_load_is_backward_compatible_without_source_coverage(self):
        result = cli_module.ScanResult(
            target="https://example.com",
            scope=["example.com"],
        )
        payload = cli_module._result_to_json(result)
        payload.pop("source_coverage", None)
        rebuilt = cli_module.ScanResult(
            target=payload.get("target", ""),
            scope=payload.get("scope", []),
            source_coverage=payload.get("source_coverage", {})
            if isinstance(payload.get("source_coverage"), dict)
            else {},
        )
        self.assertEqual(rebuilt.source_coverage, {})


if __name__ == "__main__":
    unittest.main()
