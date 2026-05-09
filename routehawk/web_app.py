from __future__ import annotations

import asyncio
import json
from datetime import datetime
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from routehawk.cli import _result_to_json, _run_scan
from routehawk.core.diff import build_endpoint_diff
from routehawk.core.models import (
    Asset,
    Endpoint,
    Finding,
    JavaScriptFile,
    MetadataRecord,
    RouteHawkConfig,
    RulesConfig,
    ScanOptions,
    ScanResult,
    ScopeConfig,
)
from routehawk.core.scope import ScopeValidator
from routehawk.reports.html import render_html
from routehawk.reports.markdown import render_markdown
from routehawk.reports.summary import build_summary
from routehawk.storage.sqlite import fetch_scan_payload, list_scan_records, record_scan


class RouteHawkWebApp:
    def __init__(self, host: str, port: int, workspace: Path):
        self.host = host
        self.port = port
        self.workspace = workspace
        self.routehawk_dir = workspace / ".routehawk"
        self.runs_root = self.routehawk_dir / "runs"
        self.run_dir = self.runs_root / "latest"
        self.triage_path = self.routehawk_dir / "triage.json"
        self.database_path = self.routehawk_dir / "routehawk.sqlite"
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def serve_forever(self) -> None:
        handler = self._handler()
        server = ThreadingHTTPServer((self.host, self.port), handler)
        print(f"RouteHawk dashboard running at http://{self.host}:{self.port}")
        server.serve_forever()

    def _handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                app.handle_get(self)

            def do_POST(self) -> None:
                app.handle_post(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        return Handler

    def handle_get(self, request: BaseHTTPRequestHandler) -> None:
        parsed_request = urlparse(request.path)
        path = parsed_request.path
        if path == "/":
            self._send_html(request, self._dashboard(parse_qs(parsed_request.query)))
            return
        if path == "/reports/latest.html":
            self._send_file(request, self.run_dir / "report.html", "text/html")
            return
        if path == "/reports/latest.md":
            self._send_file(request, self.run_dir / "report.md", "text/markdown")
            return
        if path == "/results/latest.json":
            self._send_file(request, self.run_dir / "results.json", "application/json")
            return
        if path == "/diff/latest.json":
            self._send_file(request, self.run_dir / "diff.json", "application/json")
            return
        if path == "/triage/status.json":
            self._send_json(request, {"statuses": self._read_triage_statuses()})
            return
        if path.startswith("/db/runs/"):
            self._send_database_run_file(request, path)
            return
        if path.startswith("/runs/"):
            self._send_run_file(request, path)
            return
        request.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def handle_post(self, request: BaseHTTPRequestHandler) -> None:
        path = urlparse(request.path).path
        if path == "/triage/status":
            self._handle_triage_update(request)
            return
        if path != "/scan":
            request.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_length = int(request.headers.get("Content-Length", "0"))
        body = request.rfile.read(content_length).decode("utf-8", errors="ignore")
        form = parse_qs(body)
        target = _form_value(form, "target")
        scope_text = _form_value(form, "scope")

        if not target or not scope_text:
            self._redirect(request, "/?error=missing-target-or-scope")
            return

        scope_domains = _split_scope(scope_text)
        try:
            result = self._scan(target, scope_domains)
        except Exception as exc:
            self._write_error(target, scope_domains, str(exc))
            self._redirect(request, "/?error=scan-failed")
            return

        self._write_outputs(result)
        self._redirect(request, "/?scan=complete")

    def _scan(self, target: str, scope_domains: list):
        validator = ScopeValidator(scope_domains)
        decision = validator.explain_url(target)
        if not decision.allowed:
            raise ValueError(f"Target is out of scope: {decision.reason}")

        config = RouteHawkConfig(
            program="routehawk-dashboard",
            scope=ScopeConfig(domains=scope_domains),
            rules=RulesConfig(timeout_seconds=5, max_rps_per_host=5),
            scan=ScanOptions(),
            targets=[target],
        )
        return asyncio.run(_run_scan(target, sorted(set(scope_domains)), validator, config))

    def _write_outputs(self, result) -> None:
        payload = _result_to_json(result)
        previous_payload = self._read_previous_payload()
        diff = build_endpoint_diff(previous_payload, payload)
        run_id = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        history_dir = self.runs_root / run_id
        history_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)

        results_json = json.dumps(payload, indent=2)
        diff_json = json.dumps(diff, indent=2)
        report_html = render_html(
            result,
            triage_load_url="/triage/status.json",
            triage_update_url="/triage/status",
        )
        report_md = render_markdown(result)
        summary = build_summary(result)
        metadata = {
            "run_id": run_id,
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "target": result.target,
            "scope": result.scope,
            "assets": summary.asset_count,
            "javascript_files": summary.javascript_file_count,
            "metadata": summary.metadata_count,
            "endpoints": summary.endpoint_count,
            "findings": summary.finding_count,
            "high_risk": summary.high_risk_count,
            "medium_risk": summary.medium_risk_count,
            "new_endpoints": diff["new_count"],
            "removed_endpoints": diff["removed_count"],
            "changed_endpoints": diff["changed_count"],
            "warnings": summary.warning_count,
        }
        self._write_run_files(self.run_dir, results_json, report_html, report_md, diff_json, metadata)
        self._write_run_files(history_dir, results_json, report_html, report_md, diff_json, metadata)
        record_scan(self.database_path, metadata, payload, diff)

    def _read_previous_payload(self) -> Dict[str, object]:
        path = self.run_dir / "results.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write_error(self, target: str, scope_domains: list, message: str) -> None:
        error = {
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "target": target,
            "scope": scope_domains,
            "error": message,
        }
        (self.run_dir / "summary.json").write_text(json.dumps(error, indent=2), encoding="utf-8")

    def _dashboard(self, query: Optional[Dict[str, list]] = None) -> str:
        summary, error = self._read_summary()
        diff = self._read_latest_diff()
        runs = self._recent_runs()
        latest_run_id = str(runs[0].get("run_id", "")) if runs else ""
        compare = self._build_compare_context(query or {}, runs)
        last_run = _last_run_panel(summary, error)
        diff_panel = _diff_panel(diff)
        compare_panel = _compare_panel(runs, compare)
        history = _history_panel(runs, latest_run_id)
        target_value = escape(summary.get("target", "http://localhost:8088") if summary else "http://localhost:8088")
        scope_value = escape(", ".join(summary.get("scope", ["localhost"])) if summary else "localhost")
        status_banner = _status_banner(query or {}, summary, error)

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RouteHawk Dashboard</title>
  <style>
    :root {{
      --ink: #17202a;
      --muted: #607086;
      --line: #d9e0ea;
      --panel: #ffffff;
      --soft: #f5f7fb;
      --accent: #1f5f8b;
      --danger: #b42318;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--soft);
      color: var(--ink);
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.45;
    }}
    header {{ background: #101828; color: #fff; padding: 30px 36px; }}
    header h1 {{ margin: 0 0 8px; font-size: 30px; letter-spacing: 0; }}
    header p {{ margin: 4px 0; color: #d8dee8; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 28px; }}
    .grid {{ display: grid; grid-template-columns: 1.05fr .95fr; gap: 18px; align-items: start; }}
    .panel, .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    h2 {{ margin: 0 0 14px; font-size: 21px; }}
    label {{ display: block; color: var(--muted); font-size: 13px; margin-bottom: 5px; }}
    input, textarea, button {{
      width: 100%;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 10px;
      font: inherit;
    }}
    textarea {{ min-height: 80px; resize: vertical; }}
    button {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
      font-weight: 700;
      cursor: pointer;
    }}
    button:disabled {{
      cursor: wait;
      opacity: .72;
    }}
    .field {{ margin-bottom: 14px; }}
    .hint {{ color: var(--muted); font-size: 13px; margin-top: 5px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; font-size: 26px; margin-top: 4px; }}
    .actions {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 14px; }}
    .actions a {{
      display: block;
      text-align: center;
      text-decoration: none;
      background: #eef2f7;
      color: var(--ink);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      font-weight: 700;
    }}
    .error {{ border-left: 4px solid var(--danger); background: #fff7f7; }}
    .notice {{
      border: 1px solid var(--line);
      border-left: 4px solid var(--accent);
      border-radius: 8px;
      background: #fbfcfe;
      padding: 14px 16px;
      margin-bottom: 18px;
    }}
    .notice.error {{ border-left-color: var(--danger); background: #fff7f7; }}
    .notice strong {{ display: block; margin-bottom: 4px; }}
    .history-list {{ display: grid; gap: 10px; }}
    .history-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
    }}
    .history-item p {{ margin: 4px 0; }}
    .history-item .run-id {{
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      color: var(--muted);
    }}
    .history-stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(80px, 1fr));
      gap: 6px;
      margin-top: 6px;
    }}
    .history-stat {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 6px 8px;
      font-size: 12px;
    }}
    .history-stat strong {{
      display: block;
      color: var(--ink);
      font-size: 15px;
    }}
    .history-links {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
    .history-links a {{
      text-decoration: none;
      color: var(--ink);
      background: #eef2f7;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 6px 9px;
      font-size: 13px;
      font-weight: 700;
    }}
    .diff-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
    .diff-column {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      padding: 12px;
      min-width: 0;
    }}
    .diff-column h3 {{ margin: 0 0 8px; font-size: 15px; }}
    .diff-list {{ display: grid; gap: 8px; }}
    .compare-form {{
      display: grid;
      grid-template-columns: minmax(160px, 1fr) minmax(160px, 1fr) auto;
      gap: 10px;
      align-items: end;
      margin-bottom: 12px;
    }}
    .compare-form label {{ font-size: 12px; color: var(--muted); }}
    .compare-form select {{
      width: 100%;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 8px 10px;
      font: inherit;
      background: #fff;
    }}
    .compare-form button {{
      width: auto;
      min-width: 140px;
      border-radius: 6px;
      padding: 8px 10px;
      border: 1px solid var(--accent);
      background: var(--accent);
      color: #fff;
      font-weight: 700;
    }}
    .compare-details {{
      margin-top: 14px;
      display: grid;
      gap: 12px;
    }}
    .compare-section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      padding: 12px;
    }}
    .compare-section h3 {{ margin: 0 0 8px; font-size: 15px; }}
    .compare-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .compare-table th, .compare-table td {{
      border-top: 1px solid var(--line);
      padding: 8px 6px;
      text-align: left;
      vertical-align: top;
    }}
    .compare-table th {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      border-top: 0;
    }}
    .risk-badge {{
      display: inline-block;
      min-width: 32px;
      text-align: center;
      border-radius: 999px;
      padding: 2px 8px;
      background: #eef2f7;
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 700;
    }}
    .relevance-badge {{
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      background: #fff;
      color: var(--ink);
      font-size: 12px;
      font-weight: 700;
    }}
    .relevance-low {{ opacity: .7; }}
    .diff-item {{
      border-top: 1px solid var(--line);
      padding-top: 8px;
      font-size: 13px;
    }}
    .diff-item:first-child {{ border-top: 0; padding-top: 0; }}
    .diff-item code {{ display: inline-block; max-width: 100%; }}
    .diff-meta {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
    code {{ background: #eef2f7; padding: 2px 5px; border-radius: 4px; }}
    footer {{ color: var(--muted); font-size: 12px; margin-top: 20px; }}
    @media (max-width: 860px) {{ .grid, .diff-grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <header>
    <h1>RouteHawk Dashboard</h1>
    <p>Scope-safe API and JavaScript recon assistant for authorized testing.</p>
  </header>
  <main>
    {status_banner}
    <div class="grid">
      <section class="panel">
        <h2>New Scan</h2>
        <form id="scan-form" method="post" action="/scan">
          <div class="field">
            <label for="target">Target URL</label>
            <input id="target" name="target" value="{target_value}" placeholder="https://app.example.com" required>
            <div class="hint">Use only targets you are authorized to test.</div>
          </div>
          <div class="field">
            <label for="scope">Scope domains</label>
            <textarea id="scope" name="scope" required>{scope_value}</textarea>
            <div class="hint">Comma or newline separated. Example: <code>example.com, *.example.com</code></div>
          </div>
          <button id="scan-submit" type="submit" data-default-label="Run scope-safe scan">Run scope-safe scan</button>
        </form>
      </section>
      <section class="panel">
        <h2>Latest Run</h2>
        {last_run}
      </section>
    </div>
    <section class="panel" style="margin-top: 18px;">
      <h2>Latest Diff</h2>
      {diff_panel}
    </section>
    <section class="panel" style="margin-top: 18px;">
      <h2>Run Compare</h2>
      {compare_panel}
    </section>
    <section class="panel" style="margin-top: 18px;">
      <h2>Scan History</h2>
      {history}
    </section>
    <footer>RouteHawk performs collection, classification, and manual testing guidance. It does not exploit vulnerabilities.</footer>
  </main>
  <script>
    (function () {{
      const form = document.getElementById("scan-form");
      const button = document.getElementById("scan-submit");
      if (!form || !button) return;
      form.addEventListener("submit", () => {{
        button.disabled = true;
        button.textContent = "Scanning...";
      }});
    }})();
  </script>
</body>
</html>
"""

    def _read_summary(self) -> Tuple[Dict[str, object], str]:
        path = self.run_dir / "summary.json"
        if not path.exists():
            return {}, ""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}, "Could not parse latest summary."
        return data, str(data.get("error", ""))

    def _read_latest_diff(self) -> Dict[str, object]:
        path = self.run_dir / "diff.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _read_triage_statuses(self) -> Dict[str, str]:
        if not self.triage_path.exists():
            return {}
        try:
            data = json.loads(self.triage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        statuses = data.get("statuses", {}) if isinstance(data, dict) else {}
        if not isinstance(statuses, dict):
            return {}
        allowed = {"unreviewed", "interesting", "reviewed", "ignored"}
        return {
            str(key): str(value)
            for key, value in statuses.items()
            if str(value) in allowed
        }

    def _write_triage_statuses(self, statuses: Dict[str, str]) -> None:
        self.routehawk_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "statuses": statuses,
        }
        self.triage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _handle_triage_update(self, request: BaseHTTPRequestHandler) -> None:
        content_length = int(request.headers.get("Content-Length", "0"))
        body = request.rfile.read(content_length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            request.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return
        if not isinstance(payload, dict):
            request.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return

        key = str(payload.get("key", "")).strip()
        status = str(payload.get("status", "")).strip()
        allowed = {"unreviewed", "interesting", "reviewed", "ignored"}
        if not key or status not in allowed:
            request.send_error(HTTPStatus.BAD_REQUEST, "Invalid triage update")
            return

        statuses = self._read_triage_statuses()
        if status == "unreviewed":
            statuses.pop(key, None)
        else:
            statuses[key] = status
        self._write_triage_statuses(statuses)
        self._send_json(request, {"ok": True, "statuses": statuses})

    def _recent_runs(self) -> list:
        sqlite_runs = self._recent_sqlite_runs()
        if sqlite_runs:
            return sqlite_runs
        return self._recent_file_runs()

    def _recent_sqlite_runs(self) -> list:
        records = list_scan_records(self.database_path, limit=8)
        runs = []
        for record in records:
            runs.append(
                {
                    "run_id": record.run_id,
                    "generated_at": record.generated_at,
                    "target": record.target,
                    "scope": record.scope,
                    "endpoints": record.endpoint_count,
                    "findings": record.finding_count,
                    "high_risk": record.high_risk_count,
                    "new_endpoints": record.new_endpoint_count,
                    "removed_endpoints": record.removed_endpoint_count,
                    "changed_endpoints": record.changed_endpoint_count,
                    "source": "sqlite",
                }
            )
        return runs

    def _recent_file_runs(self) -> list:
        runs = []
        if not self.runs_root.exists():
            return runs
        for path in sorted(self.runs_root.iterdir(), reverse=True):
            if not path.is_dir() or path.name == "latest":
                continue
            summary_path = path / "summary.json"
            if not summary_path.exists():
                continue
            try:
                data = json.loads(summary_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            runs.append(data)
            if len(runs) >= 8:
                break
        return runs

    def _build_compare_context(self, query: Dict[str, list], runs: list) -> Dict[str, object]:
        base = _form_value(query, "base")
        head = _form_value(query, "head")
        if not base or not head:
            return {"base": base, "head": head, "diff": None, "error": ""}
        if not _safe_run_id(base) or not _safe_run_id(head):
            return {"base": base, "head": head, "diff": None, "error": "Invalid run id."}
        if base == head:
            return {"base": base, "head": head, "diff": None, "error": "Base and head runs must differ."}
        available = {str(run.get("run_id", "")) for run in runs}
        if base not in available or head not in available:
            return {"base": base, "head": head, "diff": None, "error": "Selected runs not available in history."}

        base_payload = self._payload_for_run(base)
        head_payload = self._payload_for_run(head)
        if base_payload is None or head_payload is None:
            return {"base": base, "head": head, "diff": None, "error": "Run payload missing for comparison."}
        return {"base": base, "head": head, "diff": build_endpoint_diff(base_payload, head_payload), "error": ""}

    def _payload_for_run(self, run_id: str) -> Optional[Dict[str, object]]:
        payload = fetch_scan_payload(self.database_path, run_id, "result_json")
        if payload is not None:
            return payload
        path = self.runs_root / run_id / "results.json"
        if not path.exists():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        return loaded if isinstance(loaded, dict) else None

    def _write_run_files(
        self,
        directory: Path,
        results_json: str,
        report_html: str,
        report_md: str,
        diff_json: str,
        metadata: Dict[str, object],
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "results.json").write_text(results_json, encoding="utf-8")
        (directory / "report.html").write_text(report_html, encoding="utf-8")
        (directory / "report.md").write_text(report_md, encoding="utf-8")
        (directory / "diff.json").write_text(diff_json, encoding="utf-8")
        (directory / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def _send_run_file(self, request: BaseHTTPRequestHandler, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) != 3 or parts[0] != "runs":
            request.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        run_id = parts[1]
        filename = parts[2]
        if not _safe_run_id(run_id) or filename not in {"report.html", "report.md", "results.json", "diff.json"}:
            request.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        content_type = {
            "report.html": "text/html",
            "report.md": "text/markdown",
            "results.json": "application/json",
            "diff.json": "application/json",
        }[filename]
        self._send_file(request, self.runs_root / run_id / filename, content_type)

    def _send_database_run_file(self, request: BaseHTTPRequestHandler, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) != 4 or parts[0] != "db" or parts[1] != "runs":
            request.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        run_id = parts[2]
        filename = parts[3]
        if not _safe_run_id(run_id) or filename not in {"report.html", "report.md", "results.json", "diff.json"}:
            request.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        if filename in {"report.html", "report.md"}:
            payload = fetch_scan_payload(self.database_path, run_id, "result_json")
            if payload is None:
                request.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return
            result = _scan_result_from_payload(payload)
            if filename == "report.html":
                body = render_html(
                    result,
                    triage_load_url="/triage/status.json",
                    triage_update_url="/triage/status",
                )
                self._send_html(request, body)
            else:
                _send(
                    request,
                    HTTPStatus.OK,
                    "text/markdown; charset=utf-8",
                    render_markdown(result).encode("utf-8"),
                )
            return
        column = "result_json" if filename == "results.json" else "diff_json"
        payload = fetch_scan_payload(self.database_path, run_id, column)
        if payload is None:
            request.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        self._send_json(request, payload)

    @staticmethod
    def _send_html(request: BaseHTTPRequestHandler, body: str) -> None:
        _send(request, HTTPStatus.OK, "text/html; charset=utf-8", body.encode("utf-8"))

    @staticmethod
    def _send_file(request: BaseHTTPRequestHandler, path: Path, content_type: str) -> None:
        if not path.exists():
            request.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        _send(request, HTTPStatus.OK, content_type, path.read_bytes())

    @staticmethod
    def _send_json(request: BaseHTTPRequestHandler, payload: Dict[str, object]) -> None:
        _send(
            request,
            HTTPStatus.OK,
            "application/json",
            json.dumps(payload, indent=2).encode("utf-8"),
        )

    @staticmethod
    def _redirect(request: BaseHTTPRequestHandler, location: str) -> None:
        request.send_response(HTTPStatus.SEE_OTHER)
        request.send_header("Location", location)
        request.end_headers()


def serve_dashboard(host: str, port: int, workspace: Path) -> None:
    RouteHawkWebApp(host=host, port=port, workspace=workspace).serve_forever()


def _send(
    request: BaseHTTPRequestHandler,
    status: HTTPStatus,
    content_type: str,
    body: bytes,
) -> None:
    request.send_response(status)
    request.send_header("Content-Type", content_type)
    request.send_header("Content-Length", str(len(body)))
    request.end_headers()
    request.wfile.write(body)


def _form_value(form: Dict[str, list], key: str) -> str:
    values = form.get(key, [""])
    return values[0].strip()


def _split_scope(value: str) -> list:
    parts = []
    for chunk in value.replace(",", "\n").splitlines():
        cleaned = chunk.strip()
        if cleaned:
            parts.append(cleaned)
    return parts


def _safe_run_id(value: str) -> bool:
    return bool(value) and all(char.isdigit() or char == "-" for char in value)


def _status_banner(query: Dict[str, list], summary: Dict[str, object], error: str) -> str:
    if "scan" in query and _form_value(query, "scan") == "complete":
        findings = escape(str(summary.get("findings", 0)))
        endpoints = escape(str(summary.get("endpoints", 0)))
        return (
            '<div class="notice">'
            "<strong>Scan complete</strong>"
            f"<span>{endpoints} endpoints normalized, {findings} manual review candidates generated.</span>"
            "</div>"
        )
    error_code = _form_value(query, "error")
    if error_code:
        message = {
            "missing-target-or-scope": "Target URL and scope are required.",
            "scan-failed": error or "Scan failed. Check the latest run panel for details.",
        }.get(error_code, "Request failed.")
        return (
            '<div class="notice error">'
            "<strong>Action failed</strong>"
            f"<span>{escape(message)}</span>"
            "</div>"
        )
    return ""


def _last_run_panel(summary: Dict[str, object], error: str) -> str:
    if error:
        return f"""
        <div class="panel error">
          <strong>Last scan failed</strong>
          <p>{escape(error)}</p>
        </div>
        """
    if not summary:
        return """
        <p class="hint">No scan has been run from the dashboard yet.</p>
        <div class="actions">
          <a href="/reports/latest.html">HTML report</a>
          <a href="/results/latest.json">JSON</a>
        </div>
        """

    metrics = [
        ("Assets", summary.get("assets", 0)),
        ("JS Files", summary.get("javascript_files", 0)),
        ("Metadata", summary.get("metadata", 0)),
        ("Endpoints", summary.get("endpoints", 0)),
        ("Findings", summary.get("findings", 0)),
        ("High Risk", summary.get("high_risk", 0)),
        ("New", summary.get("new_endpoints", 0)),
        ("Removed", summary.get("removed_endpoints", 0)),
        ("Changed", summary.get("changed_endpoints", 0)),
    ]
    cards = "".join(f'<div class="metric"><span>{label}</span><strong>{value}</strong></div>' for label, value in metrics)
    generated = escape(str(summary.get("generated_at", "unknown")))
    target = escape(str(summary.get("target", "unknown")))
    return f"""
    <p class="hint">Generated at {generated}</p>
    <p>Target: <code>{target}</code></p>
    <div class="metrics">{cards}</div>
    <div class="actions">
      <a href="/reports/latest.html">HTML report</a>
      <a href="/reports/latest.md">Markdown</a>
      <a href="/results/latest.json">JSON</a>
      <a href="/diff/latest.json">Diff</a>
    </div>
    """


def _diff_panel(diff: Dict[str, object]) -> str:
    if not diff:
        return """
        <p class="hint">No scan diff has been generated yet.</p>
        <div class="actions">
          <a href="/diff/latest.json">Diff JSON</a>
        </div>
        """

    new_count = int(diff.get("new_count", 0) or 0)
    removed_count = int(diff.get("removed_count", 0) or 0)
    changed_count = int(diff.get("changed_count", 0) or 0)
    unchanged_count = int(diff.get("unchanged_count", 0) or 0)
    summary = (
        f'<p class="hint">New {new_count} | removed {removed_count} | changed {changed_count} | '
        f'unchanged {unchanged_count}</p>'
    )
    return (
        summary
        + '<div class="diff-grid">'
        + _diff_column("New endpoints", diff.get("new", []), "No new endpoints.")
        + _diff_column("Removed endpoints", diff.get("removed", []), "No removed endpoints.")
        + _diff_changed_column(diff.get("changed", []))
        + "</div>"
        + '<div class="actions"><a href="/diff/latest.json">Open Diff JSON</a></div>'
    )


def _diff_column(title: str, items: object, empty: str) -> str:
    item_list = _dict_list(items)
    sorted_items = sorted(item_list, key=lambda item: _safe_int(item.get("risk_score")), reverse=True)
    rows = [_diff_item(item) for item in sorted_items[:8]]
    if rows:
        body = _diff_count_line(len(rows), len(sorted_items)) + "".join(rows)
    else:
        body = f'<p class="hint">{escape(empty)}</p>'
    return f'<div class="diff-column"><h3>{escape(title)}</h3><div class="diff-list">{body}</div></div>'


def _diff_changed_column(items: object) -> str:
    item_list = sorted(
        _dict_list(items),
        key=lambda item: _safe_int(item.get("current_risk_score")),
        reverse=True,
    )
    rows = []
    for item in item_list[:8]:
        current_data = item.get("current", {})
        current = current_data if isinstance(current_data, dict) else {}
        deltas = item.get("deltas", {})
        delta_map = deltas if isinstance(deltas, dict) else {}
        endpoint = escape(str(item.get("endpoint", "")))
        previous_score = escape(str(item.get("previous_risk_score", 0)))
        current_score = escape(str(item.get("current_risk_score", 0)))
        confidence = _diff_confidence(current)
        relevance = _diff_relevance(current)
        sources = _diff_sources(current)
        source_urls = _safe_int(current.get("source_urls_count", 0))
        reason_count = _safe_int(current.get("risk_reason_count", 0))
        reason_preview = _diff_reason_preview(current)
        delta_lines = _changed_delta_lines(delta_map)
        rows.append(
            '<div class="diff-item">'
            f"<code>{endpoint}</code>"
            f'<div class="diff-meta">risk {previous_score} -> {current_score} | confidence {escape(confidence)} | relevance {_relevance_badge(relevance)}</div>'
            f'<div class="diff-meta">sources {sources} | source URLs {source_urls} | reasons {reason_count}</div>'
            f'<div class="diff-meta">reason preview {reason_preview}</div>'
            f"{delta_lines}"
            "</div>"
        )
    body = _diff_count_line(len(rows), len(item_list)) + "".join(rows) if rows else '<p class="hint">No changed endpoints.</p>'
    return f'<div class="diff-column"><h3>Changed endpoints</h3><div class="diff-list">{body}</div></div>'


def _diff_item(item: Dict[str, object]) -> str:
    endpoint = escape(str(item.get("endpoint", "")))
    score = escape(str(item.get("risk_score", 0)))
    confidence = escape(_diff_confidence(item))
    relevance = _diff_relevance(item)
    sources = _diff_sources(item)
    tags = _diff_tags(item)
    source_urls = escape(str(_safe_int(item.get("source_urls_count", 0))))
    reason_count = escape(str(_safe_int(item.get("risk_reason_count", 0))))
    reason_preview = _diff_reason_preview(item)
    return (
        f'<div class="diff-item relevance-{escape(relevance)}">'
        f"<code>{endpoint}</code>"
        f'<div class="diff-meta">risk {score} | confidence {confidence} | relevance {_relevance_badge(relevance)} | sources {sources}</div>'
        f'<div class="diff-meta">tags {tags}</div>'
        f'<div class="diff-meta">source URLs {source_urls} | reasons {reason_count}</div>'
        f'<div class="diff-meta">reason preview {reason_preview}</div>'
        "</div>"
    )


def _diff_sources(item: Dict[str, object]) -> str:
    sources = item.get("sources", [])
    if not isinstance(sources, list) or not sources:
        return "unknown"
    return escape(", ".join(str(source) for source in sources))


def _diff_tags(item: Dict[str, object]) -> str:
    tags = item.get("tags", [])
    if not isinstance(tags, list) or not tags:
        return "none"
    return escape(", ".join(str(tag) for tag in tags))


def _diff_confidence(item: Dict[str, object]) -> str:
    value = str(item.get("extraction_confidence", "medium")).strip().lower()
    if value in {"high", "medium", "low"}:
        return value
    return "medium"


def _diff_relevance(item: Dict[str, object]) -> str:
    value = str(item.get("app_relevance", "medium")).strip().lower()
    if value in {"high", "medium", "low"}:
        return value
    return "medium"


def _diff_reason_preview(item: Dict[str, object]) -> str:
    preview = item.get("risk_reasons_preview", [])
    if not isinstance(preview, list) or not preview:
        return "none"
    return escape(", ".join(str(reason) for reason in preview))


def _dict_list(value: object) -> list:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _diff_count_line(visible: int, total: int) -> str:
    suffix = f"Showing {visible} of {total}" if visible < total else f"Showing {visible}"
    return f'<p class="diff-meta">{escape(suffix)}</p>'


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _compare_panel(runs: list, compare: Dict[str, object]) -> str:
    if len(runs) < 2:
        return '<p class="hint">At least two scans are required for comparison.</p>'

    base = str(compare.get("base", ""))
    head = str(compare.get("head", ""))
    options = []
    for run in runs[:20]:
        run_id = str(run.get("run_id", ""))
        target = str(run.get("target", "unknown"))
        generated = str(run.get("generated_at", "unknown"))
        label = f"{run_id} | {target} | {generated}"
        options.append((run_id, label))
    if not base:
        base = options[1][0] if len(options) > 1 else options[0][0]
    if not head:
        head = options[0][0]

    base_options = "".join(
        f'<option value="{escape(run_id, quote=True)}"{" selected" if run_id == base else ""}>{escape(label)}</option>'
        for run_id, label in options
    )
    head_options = "".join(
        f'<option value="{escape(run_id, quote=True)}"{" selected" if run_id == head else ""}>{escape(label)}</option>'
        for run_id, label in options
    )
    diff = compare.get("diff")
    error = str(compare.get("error", ""))
    diff_block = (
        f'<div class="notice error"><strong>Compare failed</strong><span>{escape(error)}</span></div>'
        if error
        else _diff_panel(diff) + _compare_diff_details(diff)
        if isinstance(diff, dict)
        else '<p class="hint">Select two runs and compare.</p>'
    )
    return (
        '<form class="compare-form" method="get" action="/">'
        '<div><label for="base-run">Base run</label>'
        f'<select id="base-run" name="base">{base_options}</select></div>'
        '<div><label for="head-run">Head run</label>'
        f'<select id="head-run" name="head">{head_options}</select></div>'
        '<div><button type="submit">Compare runs</button></div>'
        "</form>"
        + diff_block
    )


def _history_panel(runs: list, latest_run_id: str = "") -> str:
    if not runs:
        return '<p class="hint">No historical dashboard scans yet.</p>'

    items = []
    for run in runs:
        run_id = escape(str(run.get("run_id", "")))
        target = escape(str(run.get("target", "unknown")))
        generated = escape(str(run.get("generated_at", "unknown")))
        findings = escape(str(run.get("findings", 0)))
        endpoints = escape(str(run.get("endpoints", 0)))
        high = escape(str(run.get("high_risk", 0)))
        new = escape(str(run.get("new_endpoints", 0)))
        removed = escape(str(run.get("removed_endpoints", 0)))
        changed = escape(str(run.get("changed_endpoints", 0)))
        source_value = str(run.get("source", "files"))
        source = escape(source_value)
        if not run_id:
            continue
        base_href = f"/db/runs/{run_id}" if source_value == "sqlite" else f"/runs/{run_id}"
        compare_href = f"/?base={run_id}&head={latest_run_id}" if latest_run_id and run_id != latest_run_id else ""
        items.append(
            f"""
            <div class="history-item">
              <p><strong>{target}</strong></p>
              <p class="run-id">run {run_id} | {generated} | source {source}</p>
              <div class="history-stats">
                <div class="history-stat"><span>endpoints</span><strong>{endpoints}</strong></div>
                <div class="history-stat"><span>findings</span><strong>{findings}</strong></div>
                <div class="history-stat"><span>high</span><strong>{high}</strong></div>
                <div class="history-stat"><span>new/removed/changed</span><strong>{new}/{removed}/{changed}</strong></div>
              </div>
              <div class="history-links">
                <a href="{base_href}/report.html">HTML</a>
                <a href="{base_href}/report.md">Markdown</a>
                <a href="{base_href}/results.json">JSON</a>
                <a href="{base_href}/diff.json">Diff</a>
                {_compare_link(compare_href)}
              </div>
            </div>
            """
        )
    if not items:
        return '<p class="hint">No historical dashboard scans yet.</p>'
    return '<div class="history-list">' + "".join(items) + "</div>"


def _scan_result_from_payload(payload: Dict[str, object]) -> ScanResult:
    return ScanResult(
        target=str(payload.get("target", "unknown")),
        scope=[str(item) for item in payload.get("scope", []) if item is not None]
        if isinstance(payload.get("scope"), list)
        else [],
        assets=[Asset(**item) for item in _dict_items(payload.get("assets"))],
        endpoints=[Endpoint(**item) for item in _dict_items(payload.get("endpoints"))],
        findings=[Finding(**item) for item in _dict_items(payload.get("findings"))],
        javascript_files=[
            JavaScriptFile(**item) for item in _dict_items(payload.get("javascript_files"))
        ],
        metadata=[MetadataRecord(**item) for item in _dict_items(payload.get("metadata"))],
        warnings=[str(item) for item in payload.get("warnings", []) if item is not None]
        if isinstance(payload.get("warnings"), list)
        else [],
    )


def _dict_items(value: object) -> list:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _compare_link(href: str) -> str:
    if not href:
        return ""
    safe_href = escape(href, quote=True)
    return f'<a href="{safe_href}">Compare vs Latest</a>'


def _compare_diff_details(diff: Dict[str, object]) -> str:
    if not diff:
        return ""
    new_items = _dict_list(diff.get("new", []))
    removed_items = _dict_list(diff.get("removed", []))
    changed_items = _dict_list(diff.get("changed", []))
    return (
        '<div class="compare-details">'
        "<h3>Detailed compare</h3>"
        + _compare_endpoint_table("New endpoints", new_items, "No new endpoints.")
        + _compare_endpoint_table("Removed endpoints", removed_items, "No removed endpoints.")
        + _compare_changed_table(changed_items, "No changed endpoints.")
        + "</div>"
    )


def _compare_endpoint_table(title: str, items: list, empty: str) -> str:
    if not items:
        return f'<div class="compare-section"><h3>{escape(title)}</h3><p class="hint">{escape(empty)}</p></div>'
    rows = []
    for item in sorted(items, key=lambda row: _safe_int(row.get("risk_score")), reverse=True):
        endpoint = escape(str(item.get("endpoint", "")))
        risk = _risk_badge(_safe_int(item.get("risk_score")))
        confidence = escape(_diff_confidence(item))
        relevance = _diff_relevance(item)
        tags = _diff_tags(item)
        sources = _diff_sources(item)
        source_urls = escape(str(_safe_int(item.get("source_urls_count", 0))))
        reason_count = escape(str(_safe_int(item.get("risk_reason_count", 0))))
        reason_preview = _diff_reason_preview(item)
        rows.append(
            f'<tr class="relevance-{escape(relevance)}">'
            f"<td><code>{endpoint}</code></td>"
            f"<td>{risk}</td>"
            f"<td>{confidence}</td>"
            f"<td>{_relevance_badge(relevance)}</td>"
            f"<td>{sources}</td>"
            f"<td>{tags}</td>"
            f"<td>source URLs {source_urls}<br>reasons {reason_count}<br>preview {reason_preview}</td>"
            "</tr>"
        )
    return (
        f'<div class="compare-section"><h3>{escape(title)}</h3>'
        '<table class="compare-table"><thead><tr>'
        "<th>Endpoint</th><th>Risk</th><th>Confidence</th><th>App Relevance</th><th>Sources</th><th>Tags</th><th>Evidence</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _compare_changed_table(items: list, empty: str) -> str:
    if not items:
        return f'<div class="compare-section"><h3>Changed endpoints</h3><p class="hint">{escape(empty)}</p></div>'
    rows = []
    for item in sorted(items, key=lambda row: _safe_int(row.get("current_risk_score")), reverse=True):
        endpoint = escape(str(item.get("endpoint", "")))
        previous = _safe_int(item.get("previous_risk_score"))
        current = _safe_int(item.get("current_risk_score"))
        current_badge = _risk_badge(current)
        current_data = item.get("current", {})
        data = current_data if isinstance(current_data, dict) else {}
        changes = item.get("deltas", {})
        delta_map = changes if isinstance(changes, dict) else {}
        sources = _diff_sources(data)
        tags = _diff_tags(data)
        confidence = _diff_confidence(data)
        relevance = _diff_relevance(data)
        source_urls = _safe_int(data.get("source_urls_count", 0))
        reason_count = _safe_int(data.get("risk_reason_count", 0))
        reason_preview = _diff_reason_preview(data)
        change_details = (
            f"<div>risk score: {escape(str(previous))} -> {escape(str(current))}</div>"
            + _changed_delta_lines(delta_map, use_blocks=True)
        )
        rows.append(
            f'<tr class="relevance-{escape(relevance)}">'
            f"<td><code>{endpoint}</code></td>"
            f"<td>{change_details}</td>"
            f"<td>{current_badge}<br>confidence {escape(confidence)}<br>relevance {_relevance_badge(relevance)}<br>sources {sources}<br>tags {tags}<br>source URLs {escape(str(source_urls))}<br>reasons {escape(str(reason_count))}<br>preview {reason_preview}</td>"
            "</tr>"
        )
    return (
        '<div class="compare-section"><h3>Changed endpoints</h3>'
        '<table class="compare-table"><thead><tr>'
        "<th>Endpoint</th><th>What changed</th><th>Current snapshot</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _changed_delta_lines(delta_map: Dict[str, object], use_blocks: bool = False) -> str:
    if not delta_map:
        return ""
    lines = []
    confidence = delta_map.get("extraction_confidence")
    if isinstance(confidence, dict):
        lines.append(_delta_line("confidence", confidence))
    relevance = delta_map.get("app_relevance")
    if isinstance(relevance, dict):
        lines.append(_delta_line("app relevance", relevance))
    tags = delta_map.get("tags")
    if isinstance(tags, dict):
        lines.append(_delta_list_line("tags", tags))
    sources = delta_map.get("sources")
    if isinstance(sources, dict):
        lines.append(_delta_list_line("sources", sources))
    source_urls = delta_map.get("source_urls")
    if isinstance(source_urls, dict):
        lines.append(_delta_list_line("source URLs", source_urls))
    reasons = delta_map.get("risk_reasons")
    if isinstance(reasons, dict):
        lines.append(_delta_list_line("risk reasons", reasons))
    if not lines:
        return ""
    if use_blocks:
        return "".join(f'<div>{line}</div>' for line in lines)
    return "".join(f'<div class="diff-meta">{line}</div>' for line in lines)


def _delta_line(label: str, payload: Dict[str, object]) -> str:
    previous = escape(str(payload.get("previous", "")))
    current = escape(str(payload.get("current", "")))
    return f"{escape(label)}: {previous} -> {current}"


def _delta_list_line(label: str, payload: Dict[str, object]) -> str:
    added = payload.get("added")
    removed = payload.get("removed")
    added_values = ", ".join(str(value) for value in added) if isinstance(added, list) and added else "none"
    removed_values = ", ".join(str(value) for value in removed) if isinstance(removed, list) and removed else "none"
    return f"{escape(label)}: +[{escape(added_values)}] -[{escape(removed_values)}]"


def _risk_badge(score: int) -> str:
    return f'<span class="risk-badge">{escape(str(score))}</span>'


def _relevance_badge(value: str) -> str:
    relevance = _diff_relevance({"app_relevance": value})
    return f'<span class="relevance-badge {escape(relevance)}">app relevance {escape(relevance)}</span>'
