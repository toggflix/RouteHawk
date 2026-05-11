import unittest

from routehawk.core.scope import ScopeValidator, normalize_scope_entries


class ScopeValidatorTests(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeValidator(["example.com", "*.example.com"])

    def test_allows_exact_domain(self):
        self.assertTrue(self.scope.is_host_allowed("example.com"))

    def test_allows_subdomain(self):
        self.assertTrue(self.scope.is_host_allowed("api.example.com"))
        self.assertTrue(self.scope.is_host_allowed("dev.api.example.com"))

    def test_denies_deceptive_suffixes(self):
        self.assertFalse(self.scope.is_host_allowed("evil-example.com"))
        self.assertFalse(self.scope.is_host_allowed("example.com.evil.com"))

    def test_denies_ip_without_cidr(self):
        self.assertFalse(self.scope.is_host_allowed("127.0.0.1"))

    def test_allows_url_with_valid_scope(self):
        self.assertTrue(self.scope.is_url_allowed("https://app.example.com/dashboard"))

    def test_normalize_scope_entries_from_url_and_wildcard(self):
        normalized, notes = normalize_scope_entries(
            ["https://www.whatnot.com", "http://localhost:8088/path", "*.example.com", "example.com"]
        )
        self.assertEqual(
            normalized,
            ["www.whatnot.com", "localhost:8088", "*.example.com", "example.com"],
        )
        self.assertIn(
            "Normalized scope entry: https://www.whatnot.com -> www.whatnot.com",
            notes,
        )
        self.assertIn(
            "Normalized scope entry: http://localhost:8088/path -> localhost:8088",
            notes,
        )

    def test_scope_with_port_matches_target_url_port(self):
        scope = ScopeValidator(["localhost:8088"])
        self.assertTrue(scope.is_url_allowed("http://localhost:8088"))
        self.assertFalse(scope.is_url_allowed("http://localhost:8090"))


if __name__ == "__main__":
    unittest.main()
