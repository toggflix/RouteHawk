from __future__ import annotations

import asyncio
import json
from datetime import datetime
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple
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
        path = urlparse(request.path).path
        if path == "/":
            self._send_html(request, self._dashboard())
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

    def _dashboard(self) -> str:
        summary, error = self._read_summary()
        diff = self._read_latest_diff()
        last_run = _last_run_panel(summary, error)
        diff_panel = _diff_panel(diff)
        history = _history_panel(self._recent_runs())
        target_value = escape(summary.get("target", "http://localhost:8088") if summary else "http://localhost:8088")
        scope_value = escape(", ".join(summary.get("scope", ["localhost"])) if summary else "localhost")

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
    .history-list {{ display: grid; gap: 10px; }}
    .history-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
    }}
    .history-item p {{ margin: 4px 0; }}
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
    rows = []
    if isinstance(items, list):
        for item in items[:8]:
            if isinstance(item, dict):
                rows.append(_diff_item(item))
    body = "".join(rows) if rows else f'<p class="hint">{escape(empty)}</p>'
    return f'<div class="diff-column"><h3>{escape(title)}</h3><div class="diff-list">{body}</div></div>'


def _diff_changed_column(items: object) -> str:
    rows = []
    if isinstance(items, list):
        for item in items[:8]:
            if not isinstance(item, dict):
                continue
            current = item.get("current", {})
            endpoint = escape(str(item.get("endpoint", "")))
            previous_score = escape(str(item.get("previous_risk_score", 0)))
            current_score = escape(str(item.get("current_risk_score", 0)))
            sources = _diff_sources(current if isinstance(current, dict) else {})
            rows.append(
                '<div class="diff-item">'
                f"<code>{endpoint}</code>"
                f'<div class="diff-meta">risk {previous_score} -> {current_score} | sources {sources}</div>'
                "</div>"
            )
    body = "".join(rows) if rows else '<p class="hint">No risk score changes.</p>'
    return f'<div class="diff-column"><h3>Changed risk</h3><div class="diff-list">{body}</div></div>'


def _diff_item(item: Dict[str, object]) -> str:
    endpoint = escape(str(item.get("endpoint", "")))
    score = escape(str(item.get("risk_score", 0)))
    sources = _diff_sources(item)
    tags = _diff_tags(item)
    return (
        '<div class="diff-item">'
        f"<code>{endpoint}</code>"
        f'<div class="diff-meta">risk {score} | sources {sources}</div>'
        f'<div class="diff-meta">tags {tags}</div>'
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


def _history_panel(runs: list) -> str:
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
        items.append(
            f"""
            <div class="history-item">
              <p><strong>{target}</strong></p>
              <p class="hint">{generated} | endpoints {endpoints} | findings {findings} | high {high} | new {new} | removed {removed} | changed {changed} | source {source}</p>
              <div class="history-links">
                <a href="{base_href}/report.html">HTML</a>
                <a href="{base_href}/report.md">Markdown</a>
                <a href="{base_href}/results.json">JSON</a>
                <a href="{base_href}/diff.json">Diff</a>
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
