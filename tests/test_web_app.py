import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.core.models import Endpoint, Finding, ScanResult
from routehawk.reports.html import render_html
from routehawk.storage.sqlite import record_scan
from routehawk.web_app import _compare_panel
from routehawk.web_app import _diff_panel
from routehawk.web_app import _history_panel
from routehawk.web_app import _scan_result_from_payload
from routehawk.web_app import _status_banner
from routehawk.web_app import RouteHawkWebApp


class WebAppTests(unittest.TestCase):
    def test_diff_panel_renders_endpoint_changes(self):
        html = _diff_panel(
            {
                "new_count": 1,
                "removed_count": 1,
                "changed_count": 1,
                "unchanged_count": 3,
                "new": [
                    {
                        "endpoint": "GET /api/admin/export",
                        "risk_score": 90,
                        "extraction_confidence": "high",
                        "app_relevance": "high",
                        "sources": ["openapi"],
                        "tags": ["admin", "data-export"],
                        "source_urls_count": 1,
                        "risk_reason_count": 2,
                        "risk_reasons_preview": ["admin keyword", "export keyword"],
                    }
                ],
                "removed": [
                    {
                        "endpoint": "GET /debug/config",
                        "risk_score": 35,
                        "extraction_confidence": "medium",
                        "app_relevance": "low",
                        "sources": ["javascript"],
                        "tags": ["debug"],
                        "source_urls_count": 1,
                        "risk_reason_count": 1,
                        "risk_reasons_preview": ["debug keyword"],
                    }
                ],
                "changed": [
                    {
                        "endpoint": "GET /api/users/{id}",
                        "previous_risk_score": 55,
                        "current_risk_score": 80,
                        "deltas": {
                            "risk_score": {"previous": 55, "current": 80},
                            "extraction_confidence": {"previous": "medium", "current": "high"},
                            "app_relevance": {"previous": "medium", "current": "high"},
                            "tags": {"added": ["billing"], "removed": []},
                            "sources": {"added": ["openapi"], "removed": []},
                        },
                        "current": {
                            "endpoint": "GET /api/users/{id}",
                            "risk_score": 80,
                            "extraction_confidence": "high",
                            "app_relevance": "high",
                            "sources": ["javascript", "openapi"],
                            "tags": ["object-reference", "billing"],
                            "source_urls_count": 2,
                            "risk_reason_count": 2,
                            "risk_reasons_preview": ["object identifier", "billing keyword"],
                        },
                    }
                ],
            }
        )

        self.assertIn("New endpoints", html)
        self.assertIn("Removed endpoints", html)
        self.assertIn("Changed endpoints", html)
        self.assertIn("/api/admin/export", html)
        self.assertIn("/debug/config", html)
        self.assertIn("risk 55 -> 80", html)
        self.assertIn("confidence: medium -> high", html)
        self.assertIn("app relevance: medium -> high", html)
        self.assertIn("app relevance high", html)
        self.assertIn("relevance-low", html)
        self.assertIn('data-dashboard-endpoint="true"', html)
        self.assertIn('data-relevance="high"', html)
        self.assertIn('data-confidence="high"', html)
        self.assertIn('data-sources="openapi"', html)
        self.assertIn('data-manual-candidate="true"', html)
        self.assertIn("sources: +[openapi] -[none]", html)
        self.assertIn("Open Diff JSON", html)
        self.assertIn("Showing 1", html)

    def test_diff_panel_sorts_by_risk_and_limits_visible_items(self):
        html = _diff_panel(
            {
                "new_count": 9,
                "removed_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "new": [
                    {
                        "endpoint": f"GET /api/items/{index}",
                        "risk_score": index,
                        "sources": [],
                        "tags": [],
                        "source_urls_count": 0,
                        "risk_reason_count": 0,
                        "risk_reasons_preview": [],
                    }
                    for index in range(9)
                ],
                "removed": [],
                "changed": [],
            }
        )

        self.assertIn("Showing 8 of 9", html)
        self.assertLess(html.index("/api/items/8"), html.index("/api/items/7"))
        self.assertNotIn("/api/items/0", html)

    def test_dashboard_triage_statuses_persist_to_workspace(self):
        with TemporaryDirectory() as temporary:
            app = RouteHawkWebApp("127.0.0.1", 0, Path(temporary))

            app._write_triage_statuses({"GET /api/users/{id}/billing": "interesting"})

            self.assertEqual(
                app._read_triage_statuses(),
                {"GET /api/users/{id}/billing": "interesting"},
            )

    def test_dashboard_report_can_use_remote_triage_api(self):
        result = ScanResult(
            target="https://example.com",
            scope=["example.com"],
            endpoints=[
                Endpoint(
                    source="javascript",
                    source_url="https://example.com/main.js",
                    method="GET",
                    raw_path="/api/users/1/billing",
                    normalized_path="/api/users/{id}/billing",
                    tags=["object-reference", "billing"],
                    risk_score=80,
                )
            ],
            findings=[
                Finding(
                    type="idor_candidate",
                    severity="high",
                    target="https://example.com",
                    endpoint="GET /api/users/{id}/billing",
                    evidence=["Contains object identifier"],
                    manual_check=["Review ownership enforcement"],
                    confidence="medium",
                )
            ],
        )

        html = render_html(
            result,
            triage_load_url="/triage/status.json",
            triage_update_url="/triage/status",
        )

        self.assertIn('const triageLoadUrl = "/triage/status.json";', html)
        self.assertIn('const triageUpdateUrl = "/triage/status";', html)
        self.assertIn("persistRemoteStatus", html)

    def test_dashboard_scan_form_has_loading_state(self):
        with TemporaryDirectory() as temporary:
            app = RouteHawkWebApp("127.0.0.1", 0, Path(temporary))

            html = app._dashboard()

            self.assertIn('id="scan-form"', html)
            self.assertIn('id="scan-submit"', html)
            self.assertIn('button.disabled = true', html)
            self.assertIn('button.textContent = "Scanning..."', html)

    def test_dashboard_endpoint_filters_render(self):
        with TemporaryDirectory() as temporary:
            app = RouteHawkWebApp("127.0.0.1", 0, Path(temporary))

            html = app._dashboard()

            self.assertIn('id="dashboard-filter-relevance"', html)
            self.assertIn('value="hide-low"', html)
            self.assertIn('id="dashboard-filter-confidence"', html)
            self.assertIn('id="dashboard-filter-source"', html)
            self.assertIn('id="dashboard-filter-manual"', html)
            self.assertIn("Manual candidates only", html)
            self.assertIn("No endpoints match the selected filters.", html)
            self.assertIn("applyEndpointFilters", html)

    def test_dashboard_status_banners_render_query_feedback(self):
        success = _status_banner({"scan": ["complete"]}, {"endpoints": 9, "findings": 8}, "")
        failure = _status_banner({"error": ["scan-failed"]}, {}, "Target is out of scope")

        self.assertIn("Scan complete", success)
        self.assertIn("9 endpoints", success)
        self.assertIn("Action failed", failure)
        self.assertIn("Target is out of scope", failure)

    def test_dashboard_history_uses_sqlite_records(self):
        with TemporaryDirectory() as temporary:
            app = RouteHawkWebApp("127.0.0.1", 0, Path(temporary))
            metadata = {
                "run_id": "20260507-120000",
                "generated_at": "2026-05-07T12:00:00Z",
                "target": "http://localhost:8088",
                "scope": ["localhost"],
                "assets": 1,
                "javascript_files": 1,
                "metadata": 5,
                "endpoints": 9,
                "findings": 8,
                "high_risk": 4,
                "medium_risk": 0,
                "new_endpoints": 2,
                "removed_endpoints": 1,
                "changed_endpoints": 3,
            }
            record_scan(app.database_path, metadata, {"endpoints": []}, {"new_count": 2})

            runs = app._recent_runs()
            html = _history_panel(runs, latest_run_id="20260507-120001")

            self.assertEqual(runs[0]["source"], "sqlite")
            self.assertIn("source sqlite", html)
            self.assertIn("2/1/3", html)
            self.assertIn("/db/runs/20260507-120000/report.html", html)
            self.assertIn("/db/runs/20260507-120000/report.md", html)
            self.assertIn("/db/runs/20260507-120000/results.json", html)
            self.assertIn("/db/runs/20260507-120000/diff.json", html)
            self.assertIn("Compare vs Latest", html)

    def test_file_history_keeps_file_links(self):
        html = _history_panel(
            [
                {
                    "run_id": "20260507-120000",
                    "generated_at": "2026-05-07T12:00:00Z",
                    "target": "http://localhost:8088",
                    "endpoints": 9,
                    "findings": 8,
                    "high_risk": 4,
                }
            ]
        )

        self.assertIn("/runs/20260507-120000/results.json", html)
        self.assertIn("/runs/20260507-120000/diff.json", html)

    def test_compare_panel_renders_form_and_diff(self):
        runs = [
            {"run_id": "20260507-120002", "target": "http://localhost:8088", "generated_at": "t2"},
            {"run_id": "20260507-120001", "target": "http://localhost:8088", "generated_at": "t1"},
        ]
        compare = {
            "base": "20260507-120001",
            "head": "20260507-120002",
            "diff": {
                "new_count": 1,
                "removed_count": 0,
                "changed_count": 0,
                "unchanged_count": 0,
                "new": [
                    {
                        "endpoint": "GET /api/billing/{id}",
                        "risk_score": 90,
                        "extraction_confidence": "high",
                        "app_relevance": "high",
                        "sources": ["openapi"],
                        "tags": ["billing", "object-reference"],
                        "source_urls_count": 1,
                        "risk_reason_count": 1,
                        "risk_reasons_preview": ["billing keyword"],
                    }
                ],
                "removed": [],
                "changed": [
                    {
                        "endpoint": "GET /api/users/{id}",
                        "previous_risk_score": 55,
                        "current_risk_score": 80,
                        "deltas": {
                            "risk_score": {"previous": 55, "current": 80},
                            "extraction_confidence": {"previous": "medium", "current": "high"},
                            "app_relevance": {"previous": "medium", "current": "high"},
                        },
                        "current": {
                            "endpoint": "GET /api/users/{id}",
                            "risk_score": 80,
                            "extraction_confidence": "high",
                            "app_relevance": "high",
                            "sources": ["javascript", "openapi"],
                            "tags": ["object-reference"],
                            "source_urls_count": 2,
                            "risk_reason_count": 1,
                            "risk_reasons_preview": ["object identifier"],
                        },
                    }
                ],
            },
            "error": "",
        }

        html = _compare_panel(runs, compare)

        self.assertIn("Compare runs", html)
        self.assertIn('name="base"', html)
        self.assertIn('name="head"', html)
        self.assertIn("New endpoints", html)
        self.assertIn("Detailed compare", html)
        self.assertIn("/api/billing/{id}", html)
        self.assertIn("Changed endpoints", html)
        self.assertIn("risk score: 55 -> 80", html)
        self.assertIn("confidence: medium -> high", html)
        self.assertIn("app relevance: medium -> high", html)
        self.assertIn("App Relevance", html)
        self.assertIn("app relevance high", html)
        self.assertIn('data-dashboard-endpoint="true"', html)
        self.assertIn('data-relevance="high"', html)
        self.assertIn('data-confidence="high"', html)
        self.assertIn('data-sources="openapi"', html)
        self.assertIn("risk-badge", html)

    def test_compare_panel_shows_empty_states_for_sections(self):
        runs = [
            {"run_id": "20260507-120002", "target": "http://localhost:8088", "generated_at": "t2"},
            {"run_id": "20260507-120001", "target": "http://localhost:8088", "generated_at": "t1"},
        ]
        compare = {
            "base": "20260507-120001",
            "head": "20260507-120002",
            "diff": {
                "new_count": 0,
                "removed_count": 0,
                "changed_count": 0,
                "unchanged_count": 2,
                "new": [],
                "removed": [],
                "changed": [],
            },
            "error": "",
        }

        html = _compare_panel(runs, compare)

        self.assertIn("No new endpoints", html)
        self.assertIn("No removed endpoints", html)
        self.assertIn("No changed endpoints", html)

    def test_compare_context_builds_diff_for_known_runs(self):
        with TemporaryDirectory() as temporary:
            app = RouteHawkWebApp("127.0.0.1", 0, Path(temporary))
            record_scan(
                app.database_path,
                {
                    "run_id": "20260507-120001",
                    "generated_at": "2026-05-07T12:00:01Z",
                    "target": "http://localhost:8088",
                    "scope": ["localhost"],
                    "assets": 1,
                    "javascript_files": 1,
                    "metadata": 5,
                    "endpoints": 1,
                    "findings": 0,
                    "high_risk": 0,
                    "medium_risk": 0,
                    "new_endpoints": 0,
                    "removed_endpoints": 0,
                    "changed_endpoints": 0,
                },
                {"endpoints": [{"method": "GET", "normalized_path": "/api/a"}]},
                {"new_count": 0},
            )
            record_scan(
                app.database_path,
                {
                    "run_id": "20260507-120002",
                    "generated_at": "2026-05-07T12:00:02Z",
                    "target": "http://localhost:8088",
                    "scope": ["localhost"],
                    "assets": 1,
                    "javascript_files": 1,
                    "metadata": 5,
                    "endpoints": 2,
                    "findings": 0,
                    "high_risk": 0,
                    "medium_risk": 0,
                    "new_endpoints": 0,
                    "removed_endpoints": 0,
                    "changed_endpoints": 0,
                },
                {"endpoints": [{"method": "GET", "normalized_path": "/api/a"}, {"method": "GET", "normalized_path": "/api/b"}]},
                {"new_count": 0},
            )

            runs = app._recent_runs()
            context = app._build_compare_context({"base": ["20260507-120001"], "head": ["20260507-120002"]}, runs)

            self.assertEqual(context["error"], "")
            self.assertEqual(context["diff"]["new_count"], 1)

    def test_rebuilds_scan_result_from_json_payload(self):
        result = _scan_result_from_payload(
            {
                "target": "http://localhost:8088",
                "scope": ["localhost"],
                "assets": [
                    {
                        "host": "localhost",
                        "scheme": "http",
                        "ip": None,
                        "status": 200,
                        "title": "Demo",
                        "technologies": [],
                    }
                ],
                "endpoints": [
                    {
                        "source": "javascript",
                        "source_url": "http://localhost:8088/static/main.js",
                        "method": "GET",
                        "raw_path": "/api/users/1/billing",
                        "normalized_path": "/api/users/{id}/billing",
                        "parameters": [],
                        "tags": ["object-reference"],
                        "risk_score": 80,
                        "app_relevance": "high",
                        "sources": ["javascript"],
                        "source_urls": ["http://localhost:8088/static/main.js"],
                        "raw_paths": ["/api/users/1/billing"],
                        "evidence": [],
                    }
                ],
                "findings": [],
                "javascript_files": [],
                "metadata": [],
                "warnings": [],
            }
        )

        self.assertEqual(result.target, "http://localhost:8088")
        self.assertEqual(result.assets[0].host, "localhost")
        self.assertEqual(result.endpoints[0].normalized_path, "/api/users/{id}/billing")


if __name__ == "__main__":
    unittest.main()
