import unittest

from routehawk.analyzers.route_normalizer import normalize_path


class RouteNormalizerTests(unittest.TestCase):
    def test_normalizes_integer_ids(self):
        self.assertEqual(normalize_path("/api/users/123/billing"), "/api/users/{id}/billing")

    def test_normalizes_uuid(self):
        raw = "/api/orders/550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(normalize_path(raw), "/api/orders/{uuid}")

    def test_normalizes_colon_params(self):
        self.assertEqual(normalize_path("/users/:id/profile"), "/users/{id}/profile")

    def test_normalizes_query_values(self):
        self.assertEqual(normalize_path("/api/users?id=123&tab=billing"), "/api/users?id={value}&tab={value}")


if __name__ == "__main__":
    unittest.main()

