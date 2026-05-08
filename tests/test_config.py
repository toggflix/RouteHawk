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


if __name__ == "__main__":
    unittest.main()
