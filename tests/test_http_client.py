from __future__ import annotations

import unittest
from dataclasses import dataclass

from routehawk.core.http_client import RequestBudgetExceeded, ScopeSafeHttpClient
from routehawk.core.models import RulesConfig
from routehawk.core.scope import ScopeValidator


@dataclass
class _FakeResponse:
    url: str
    status_code: int
    headers: dict
    text: str = ""


class _RetryClient(ScopeSafeHttpClient):
    def __init__(self, responses, rules):
        super().__init__(ScopeValidator(["example.com"]), rules)
        self._responses = list(responses)
        self.calls = 0

    async def _send_request(self, method: str, url: str, body: str = ""):
        del method, url, body
        self.calls += 1
        return self._responses.pop(0)


class HttpClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_retries_idempotent_requests(self):
        client = _RetryClient(
            responses=[
                _FakeResponse("https://example.com/a", 429, {"Retry-After": "0"}),
                _FakeResponse("https://example.com/a", 200, {}),
            ],
            rules=RulesConfig(max_retries=2, retry_backoff_seconds=0.01, max_rps_per_host=1000),
        )

        response = await client.request_text("GET", "https://example.com/a")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.calls, 2)

    async def test_does_not_retry_non_idempotent_requests(self):
        client = _RetryClient(
            responses=[
                _FakeResponse("https://example.com/a", 503, {}),
                _FakeResponse("https://example.com/a", 200, {}),
            ],
            rules=RulesConfig(max_retries=2, retry_backoff_seconds=0.01, max_rps_per_host=1000),
        )

        response = await client.request_text("POST", "https://example.com/a")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(client.calls, 1)

    def test_parse_retry_after_seconds(self):
        self.assertEqual(ScopeSafeHttpClient._parse_retry_after("3"), 3.0)
        self.assertIsNone(ScopeSafeHttpClient._parse_retry_after("bad-value"))

    async def test_enforces_request_budget_per_scan(self):
        client = _RetryClient(
            responses=[
                _FakeResponse("https://example.com/a", 200, {}),
                _FakeResponse("https://example.com/b", 200, {}),
            ],
            rules=RulesConfig(
                request_budget_per_scan=1,
                max_rps_per_host=1000,
                max_retries=0,
            ),
        )

        first = await client.request_text("GET", "https://example.com/a")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(client.calls, 1)

        with self.assertRaises(RequestBudgetExceeded):
            await client.request_text("GET", "https://example.com/b")
        self.assertEqual(client.calls, 1)

    async def test_budget_non_positive_is_unlimited(self):
        for budget in (0, -10):
            client = _RetryClient(
                responses=[
                    _FakeResponse("https://example.com/a", 200, {}),
                    _FakeResponse("https://example.com/b", 200, {}),
                    _FakeResponse("https://example.com/c", 200, {}),
                ],
                rules=RulesConfig(
                    request_budget_per_scan=budget,
                    max_rps_per_host=1000,
                    max_retries=0,
                ),
            )

            await client.request_text("GET", "https://example.com/a")
            await client.request_text("GET", "https://example.com/b")
            await client.request_text("GET", "https://example.com/c")
            self.assertEqual(client.calls, 3)


if __name__ == "__main__":
    unittest.main()
