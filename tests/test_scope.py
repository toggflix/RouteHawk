import unittest

from routehawk.core.scope import ScopeValidator


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


if __name__ == "__main__":
    unittest.main()

