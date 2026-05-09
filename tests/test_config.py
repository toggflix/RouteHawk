import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.core.config import load_config


class ConfigTests(unittest.TestCase):
    def test_loads_suppression_rules(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "routehawk.yaml"
            path.write_text(
                """
program: test-program
targets:
  - https://app.example.com
scope:
  domains:
    - example.com
scan:
  check_auth_behavior: true
  auth_probe_limit: 7
rules:
  max_retries: 4
  retry_backoff_seconds: 0.75
  respect_retry_after: false
  request_budget_per_scan: 321
suppression:
  ignore_suffixes:
    - .bak
  ignore_path_prefixes:
    - /noise/
  ignore_regexes:
    - /api/internal/cache/\\d+
""",
                encoding="utf-8",
            )

            config = load_config(str(path))

            self.assertEqual(config.suppression.ignore_suffixes, [".bak"])
            self.assertEqual(config.suppression.ignore_path_prefixes, ["/noise/"])
            self.assertEqual(config.suppression.ignore_regexes, ["/api/internal/cache/\\d+"])
            self.assertTrue(config.scan.check_auth_behavior)
            self.assertEqual(config.scan.auth_probe_limit, 7)
            self.assertEqual(config.rules.max_retries, 4)
            self.assertAlmostEqual(config.rules.retry_backoff_seconds, 0.75)
            self.assertFalse(config.rules.respect_retry_after)
            self.assertEqual(config.rules.request_budget_per_scan, 321)

    def test_load_config_defaults_remain_backward_compatible(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "routehawk-minimal.yaml"
            path.write_text(
                """
program: test-program
targets:
  - https://app.example.com
scope:
  domains:
    - example.com
""",
                encoding="utf-8",
            )

            config = load_config(str(path))

            self.assertEqual(config.rules.max_rps_per_host, 1)
            self.assertEqual(config.rules.max_concurrency, 2)
            self.assertEqual(config.rules.max_retries, 1)
            self.assertAlmostEqual(config.rules.retry_backoff_seconds, 1.0)
            self.assertTrue(config.rules.respect_retry_after)
            self.assertEqual(config.rules.request_budget_per_scan, 500)
            self.assertFalse(config.scan.check_auth_behavior)
            self.assertEqual(config.scan.auth_probe_limit, 0)


if __name__ == "__main__":
    unittest.main()
