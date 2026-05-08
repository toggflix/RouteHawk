from __future__ import annotations

import json
from html import escape

from routehawk.analyzers.idor_candidates import severity_for_score
from routehawk.core.models import Endpoint, ScanResult
from routehawk.reports.summary import build_summary


def render_html(result: ScanResult, triage_load_url: str = "", triage_update_url: str = "") -> str:
    summary = build_summary(result)
    cards = _summary_cards(summary)
    source_options = _select_options(summary.source_counts.keys())
    type_options = _select_options(sorted({finding.type for finding in result.findings}))
    assets = _asset_rows(result)
    javascript_files = _javascript_rows(result)
    metadata = _metadata_rows(result)
    findings = _finding_cards(result)
    endpoints = _endpoint_rows(result)
    warnings = _warnings(result)
    source_coverage = _count_list(summary.source_counts, empty="No endpoint sources recorded.")
    tag_coverage = _count_list(summary.tag_counts, empty="No classifier tags recorded.")
    route_groups = _route_group_rows(summary.route_groups)
    triage_load = json.dumps(triage_load_url)
    triage_update = json.dumps(triage_update_url)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RouteHawk Report</title>
  <style>
    :root {{
      --ink: #18212f;
      --muted: #637083;
      --line: #d9e0ea;
      --panel: #ffffff;
      --soft: #f6f8fb;
      --high: #b42318;
      --medium: #b66d00;
      --low: #276749;
      --accent: #1f5f8b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--soft);
      color: var(--ink);
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: #101828;
      color: #fff;
      padding: 28px 36px;
    }}
    header h1 {{ margin: 0 0 8px; font-size: 30px; letter-spacing: 0; }}
    header p {{ margin: 4px 0; color: #d8dee8; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    section {{ margin: 0 0 28px; }}
    h2 {{ margin: 0 0 14px; font-size: 21px; letter-spacing: 0; }}
    h3 {{ margin: 0 0 10px; font-size: 17px; letter-spacing: 0; }}
    code {{
      background: #eef2f7;
      color: #111827;
      padding: 2px 5px;
      border-radius: 4px;
      word-break: break-word;
    }}
    .grid {{ display: grid; gap: 14px; }}
    .summary {{ grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }}
    .columns {{ grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }}
    .metric, .panel, .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; font-size: 28px; margin-top: 4px; }}
    .toolbar {{
      display: grid;
      grid-template-columns: minmax(220px, 1fr) repeat(4, minmax(140px, 180px)) auto;
      gap: 10px;
      align-items: end;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    label {{ display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }}
    input, select, button {{
      width: 100%;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      font: inherit;
      padding: 8px 10px;
    }}
    button {{
      cursor: pointer;
      background: #1f5f8b;
      border-color: #1f5f8b;
      color: #fff;
      font-weight: 600;
    }}
    button.secondary {{
      background: #fff;
      border-color: #cbd5e1;
      color: var(--ink);
    }}
    button.copy {{
      width: auto;
      margin-top: 8px;
      padding: 6px 10px;
      font-size: 13px;
    }}
    .triage {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
      align-items: center;
    }}
    .triage button {{
      width: auto;
      background: #fff;
      color: var(--ink);
      border-color: #cbd5e1;
      padding: 6px 10px;
      font-size: 13px;
    }}
    .triage button.active {{
      background: #1f5f8b;
      color: #fff;
      border-color: #1f5f8b;
    }}
    .status-badge {{
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 9px;
      background: #fbfcfe;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }}
    .status-line {{ color: var(--muted); font-size: 13px; margin: 10px 0 0; }}
    .finding {{ border-left: 5px solid var(--high); margin-bottom: 14px; }}
    .finding.medium {{ border-left-color: var(--medium); }}
    .finding.low, .finding.info {{ border-left-color: var(--low); }}
    .meta {{ color: var(--muted); font-size: 13px; }}
    ul {{ margin: 8px 0 0; padding-left: 20px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    th {{ background: #edf1f6; color: #344054; }}
    tr:last-child td {{ border-bottom: 0; }}
    .pill {{
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      margin: 0 4px 4px 0;
      background: #fbfcfe;
      font-size: 12px;
      color: #344054;
    }}
    .score {{ font-weight: 700; }}
    .score.high {{ color: var(--high); }}
    .score.medium {{ color: var(--medium); }}
    .score.low, .score.info {{ color: var(--low); }}
    .hidden {{ display: none !important; }}
    .empty {{ color: var(--muted); }}
    footer {{ color: var(--muted); font-size: 12px; padding: 6px 0 22px; }}
    @media (max-width: 860px) {{
      .toolbar {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>RouteHawk Report</h1>
    <p>Scope-safe API and JavaScript reconnaissance summary</p>
    <p><strong>Target:</strong> <code>{escape(result.target)}</code></p>
    <p><strong>Scope:</strong> {escape(", ".join(result.scope) if result.scope else "not recorded")}</p>
  </header>
  <main>
    <section>
      <h2>Executive Summary</h2>
      <div class="grid summary">{cards}</div>
    </section>
    <section>
      <h2>Filters</h2>
      <div class="toolbar">
        <div>
          <label for="filter-search">Search</label>
          <input id="filter-search" type="search" placeholder="Route, tag, evidence, source">
        </div>
        <div>
          <label for="filter-severity">Severity</label>
          <select id="filter-severity">
            <option value="all">All severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div>
          <label for="filter-source">Source</label>
          <select id="filter-source">
            <option value="all">All sources</option>
            {source_options}
          </select>
        </div>
        <div>
          <label for="filter-type">Finding Type</label>
          <select id="filter-type">
            <option value="all">All types</option>
            {type_options}
          </select>
        </div>
        <div>
          <label for="filter-status">Review Status</label>
          <select id="filter-status">
            <option value="all">All statuses</option>
            <option value="unreviewed">Unreviewed</option>
            <option value="interesting">Interesting</option>
            <option value="reviewed">Reviewed</option>
            <option value="ignored">Ignored</option>
          </select>
        </div>
        <button id="filter-reset" class="secondary" type="button">Reset</button>
      </div>
      <p class="status-line"><span id="visible-findings">0</span> findings and <span id="visible-endpoints">0</span> endpoints visible.</p>
    </section>
    <section class="grid columns">
      <div class="panel">
        <h2>Source Coverage</h2>
        {source_coverage}
      </div>
      <div class="panel">
        <h2>Classifier Tags</h2>
        {tag_coverage}
      </div>
    </section>
    <section>
      <h2>Route Groups</h2>
      {route_groups}
    </section>
    <section>
      <h2>Top Manual Test Candidates</h2>
      {findings}
    </section>
    <section>
      <h2>Discovered Assets</h2>
      {assets}
    </section>
    <section class="grid columns">
      <div class="panel">
        <h2>JavaScript Files</h2>
        {javascript_files}
      </div>
      <div class="panel">
        <h2>Metadata</h2>
        {metadata}
      </div>
    </section>
    <section>
      <h2>Endpoint Inventory</h2>
      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Route</th>
            <th>Risk</th>
            <th>Extraction Confidence</th>
            <th>Sources</th>
            <th>Tags</th>
            <th>Risk Signals</th>
          </tr>
        </thead>
        <tbody>{endpoints}</tbody>
      </table>
    </section>
    <section>
      <h2>Warnings</h2>
      {warnings}
    </section>
    <footer>Generated by RouteHawk. This report provides prioritization and manual testing guidance only.</footer>
  </main>
  <script>
    (function () {{
      const search = document.getElementById("filter-search");
      const severity = document.getElementById("filter-severity");
      const source = document.getElementById("filter-source");
      const type = document.getElementById("filter-type");
      const status = document.getElementById("filter-status");
      const reset = document.getElementById("filter-reset");
      const findingCount = document.getElementById("visible-findings");
      const endpointCount = document.getElementById("visible-endpoints");
      const findings = Array.from(document.querySelectorAll("[data-report-item='finding']"));
      const endpoints = Array.from(document.querySelectorAll("[data-report-item='endpoint']"));
      const storagePrefix = "routehawk:triage:" + window.location.pathname + ":";
      const triageLoadUrl = {triage_load};
      const triageUpdateUrl = {triage_update};

      function tokens(value) {{
        return (value || "").split(" ").filter(Boolean);
      }}

      function visibleByCommonFilters(element) {{
        const query = search.value.trim().toLowerCase();
        const severityValue = severity.value;
        const sourceValue = source.value;
        const text = element.dataset.search || "";
        const sourceTokens = tokens(element.dataset.sources || "");

        if (query && !text.includes(query)) return false;
        if (severityValue !== "all" && element.dataset.severity !== severityValue) return false;
        if (sourceValue !== "all" && !sourceTokens.includes(sourceValue)) return false;
        return true;
      }}

      function applyFilters() {{
        let shownFindings = 0;
        let shownEndpoints = 0;
        const typeValue = type.value;
        const statusValue = status.value;

        findings.forEach((element) => {{
          const visible =
            visibleByCommonFilters(element) &&
            (typeValue === "all" || element.dataset.type === typeValue) &&
            (statusValue === "all" || element.dataset.status === statusValue);
          element.classList.toggle("hidden", !visible);
          if (visible) shownFindings += 1;
        }});

        endpoints.forEach((element) => {{
          const visible = visibleByCommonFilters(element);
          element.classList.toggle("hidden", !visible);
          if (visible) shownEndpoints += 1;
        }});

        findingCount.textContent = String(shownFindings);
        endpointCount.textContent = String(shownEndpoints);
      }}

      function setStatus(card, value, persist) {{
        if (persist === undefined) persist = true;
        card.dataset.status = value;
        const badge = card.querySelector("[data-status-badge]");
        if (badge) badge.textContent = value;
        card.querySelectorAll("[data-triage]").forEach((button) => {{
          button.classList.toggle("active", button.dataset.triage === value);
        }});
        if (persist) {{
          try {{
            window.localStorage.setItem(storagePrefix + card.dataset.key, value);
          }} catch (error) {{
            // localStorage can be unavailable in hardened browser settings.
          }}
          persistRemoteStatus(card.dataset.key, value);
        }}
        applyFilters();
      }}

      function persistRemoteStatus(key, value) {{
        if (!triageUpdateUrl) return;
        fetch(triageUpdateUrl, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ key: key, status: value }})
        }}).catch(() => {{}});
      }}

      async function loadRemoteStatuses() {{
        if (!triageLoadUrl) return {{}};
        try {{
          const response = await fetch(triageLoadUrl, {{ cache: "no-store" }});
          if (!response.ok) return {{}};
          const payload = await response.json();
          return payload && payload.statuses ? payload.statuses : {{}};
        }} catch (error) {{
          return {{}};
        }}
      }}

      findings.forEach((card) => {{
        let saved = "unreviewed";
        try {{
          saved = window.localStorage.getItem(storagePrefix + card.dataset.key) || "unreviewed";
        }} catch (error) {{
          saved = "unreviewed";
        }}
        setStatus(card, saved, false);
        card.querySelectorAll("[data-triage]").forEach((button) => {{
          button.addEventListener("click", () => setStatus(card, button.dataset.triage, true));
        }});
      }});

      loadRemoteStatuses().then((statuses) => {{
        findings.forEach((card) => {{
          const value = statuses[card.dataset.key];
          if (value) setStatus(card, value, false);
        }});
      }});

      document.querySelectorAll("[data-copy-checklist]").forEach((button) => {{
        button.addEventListener("click", async () => {{
          const text = button.dataset.copyChecklist || "";
          try {{
            await navigator.clipboard.writeText(text);
            button.textContent = "Copied";
            window.setTimeout(() => {{ button.textContent = "Copy checklist"; }}, 1200);
          }} catch (error) {{
            button.textContent = "Copy failed";
            window.setTimeout(() => {{ button.textContent = "Copy checklist"; }}, 1200);
          }}
        }});
      }});

      document.querySelectorAll("[data-copy-draft]").forEach((button) => {{
        button.addEventListener("click", async () => {{
          const text = button.dataset.copyDraft || "";
          try {{
            await navigator.clipboard.writeText(text);
            button.textContent = "Draft copied";
            window.setTimeout(() => {{ button.textContent = "Copy finding draft"; }}, 1200);
          }} catch (error) {{
            button.textContent = "Copy failed";
            window.setTimeout(() => {{ button.textContent = "Copy finding draft"; }}, 1200);
          }}
        }});
      }});

      [search, severity, source, type, status].forEach((control) => {{
        control.addEventListener("input", applyFilters);
        control.addEventListener("change", applyFilters);
      }});
      reset.addEventListener("click", () => {{
        search.value = "";
        severity.value = "all";
        source.value = "all";
        type.value = "all";
        status.value = "all";
        applyFilters();
      }});
      applyFilters();
    }})();
  </script>
</body>
</html>
"""


def _summary_cards(summary) -> str:
    metrics = [
        ("Assets", summary.asset_count),
        ("JS Files", summary.javascript_file_count),
        ("Metadata", summary.metadata_count),
        ("Endpoints", summary.endpoint_count),
        ("Findings", summary.finding_count),
        ("High Risk", summary.high_risk_count),
        ("Medium Risk", summary.medium_risk_count),
        ("Warnings", summary.warning_count),
    ]
    return "".join(f'<div class="metric"><span>{label}</span><strong>{value}</strong></div>' for label, value in metrics)


def _finding_cards(result: ScanResult) -> str:
    if not result.findings:
        return '<p class="empty">No high-risk manual test candidates recorded yet.</p>'

    cards = []
    endpoints = {f"{endpoint.method} {endpoint.normalized_path}": endpoint for endpoint in result.endpoints}
    for finding in result.findings:
        severity = escape(finding.severity)
        endpoint = endpoints.get(finding.endpoint)
        sources = endpoint.sources if endpoint else []
        source_data = escape(" ".join(sources), quote=True)
        key = escape(finding.endpoint, quote=True)
        search_data = escape(
            " ".join(
                [
                    finding.endpoint,
                    finding.type,
                    finding.severity,
                    " ".join(finding.evidence),
                    " ".join(finding.manual_check),
                    " ".join(sources),
                ]
            ).lower(),
            quote=True,
        )
        checklist = escape("\n".join(finding.manual_check), quote=True)
        draft = escape(_finding_draft(finding), quote=True)
        evidence = "".join(f"<li>{escape(item)}</li>" for item in finding.evidence)
        manual = "".join(f"<li>{escape(item)}</li>" for item in finding.manual_check)
        cards.append(
            f'<article class="finding {severity}" data-report-item="finding" data-key="{key}" data-status="unreviewed" data-severity="{severity}" data-type="{escape(finding.type, quote=True)}" data-sources="{source_data}" data-search="{search_data}">'
            f"<h3>[{escape(finding.severity.title())}] <code>{escape(finding.endpoint)}</code></h3>"
            f'<p class="meta">Type: {escape(finding.type)} | Confidence: {escape(finding.confidence)} | Status: <span class="status-badge" data-status-badge>unreviewed</span></p>'
            "<h4>Evidence</h4>"
            f"<ul>{evidence}</ul>"
            "<h4>Manual Test Plan</h4>"
            f"<ul>{manual}</ul>"
            f'<button class="copy" type="button" data-copy-checklist="{checklist}">Copy checklist</button>'
            f'<button class="copy" type="button" data-copy-draft="{draft}">Copy finding draft</button>'
            '<div class="triage">'
            '<button type="button" data-triage="interesting">Interesting</button>'
            '<button type="button" data-triage="reviewed">Reviewed</button>'
            '<button type="button" data-triage="ignored">Ignore</button>'
            '<button type="button" data-triage="unreviewed">Clear</button>'
            "</div>"
            "</article>"
        )
    return "".join(cards)


def _asset_rows(result: ScanResult) -> str:
    if not result.assets:
        return '<p class="empty">No assets recorded.</p>'

    rows = []
    for asset in result.assets:
        technologies = ", ".join(asset.technologies) if asset.technologies else "unknown"
        rows.append(
            "<tr>"
            f"<td><code>{escape(asset.scheme)}://{escape(asset.host)}</code></td>"
            f"<td>{asset.status or 'n/a'}</td>"
            f"<td>{escape(asset.title or 'untitled')}</td>"
            f"<td>{escape(technologies)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Asset</th><th>Status</th><th>Title</th><th>Technologies</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _javascript_rows(result: ScanResult) -> str:
    if not result.javascript_files:
        return '<p class="empty">No JavaScript files analyzed.</p>'

    rows = []
    for item in result.javascript_files:
        rows.append(
            "<tr>"
            f"<td><code>{escape(item.url)}</code></td>"
            f"<td>{item.size}</td>"
            f"<td>{item.endpoints_found}</td>"
            f"<td><code>{escape(item.sha256[:16])}</code></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>URL</th><th>Bytes</th><th>Endpoints</th><th>SHA-256</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _metadata_rows(result: ScanResult) -> str:
    if not result.metadata:
        return '<p class="empty">No metadata records collected.</p>'

    rows = []
    for item in result.metadata:
        detail_text = ", ".join(f"{key}: {value}" for key, value in item.details.items())
        rows.append(
            "<tr>"
            f"<td>{escape(item.source)}</td>"
            f"<td>{item.status or 'n/a'}</td>"
            f"<td><code>{escape(item.url)}</code></td>"
            f"<td>{escape(detail_text)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Source</th><th>Status</th><th>URL</th><th>Details</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _endpoint_rows(result: ScanResult) -> str:
    if not result.endpoints:
        return '<tr><td colspan="7" class="empty">No endpoints recorded yet.</td></tr>'
    return "".join(_endpoint_row(endpoint) for endpoint in result.endpoints)


def _route_group_rows(groups: list) -> str:
    if not groups:
        return '<p class="empty">No route groups recorded.</p>'
    rows = []
    for group in groups:
        methods = ", ".join(group.methods) if group.methods else "n/a"
        tags = _pills(group.tags[:10]) if group.tags else '<span class="empty">none</span>'
        rows.append(
            "<tr>"
            f"<td><code>{escape(group.prefix)}</code></td>"
            f"<td>{group.count}</td>"
            f"<td>{group.max_risk_score}</td>"
            f"<td>{escape(methods)}</td>"
            f"<td>{tags}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Prefix</th><th>Routes</th><th>Max Risk</th><th>Methods</th><th>Tags</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _endpoint_row(endpoint: Endpoint) -> str:
    severity = severity_for_score(endpoint.risk_score)
    sources = endpoint.sources or [endpoint.source]
    source_urls = endpoint.source_urls or [endpoint.source_url]
    tags = endpoint.tags or []
    reasons = endpoint.risk_reasons[:4]
    source_title = "\n".join(source_urls)
    tag_html = _pills(tags) if tags else '<span class="empty">none</span>'
    reason_html = (
        "<ul>" + "".join(f"<li>{escape(reason)}</li>" for reason in reasons) + "</ul>"
        if reasons
        else '<span class="empty">none</span>'
    )
    source_data = escape(" ".join(sources), quote=True)
    search_data = escape(
        " ".join(
            [
                endpoint.method,
                endpoint.normalized_path,
                " ".join(endpoint.raw_paths or [endpoint.raw_path]),
                " ".join(sources),
                " ".join(tags),
            ]
        ).lower(),
        quote=True,
    )
    return (
        f'<tr data-report-item="endpoint" data-severity="{severity}" data-sources="{source_data}" data-search="{search_data}">'
        f"<td>{escape(endpoint.method)}</td>"
        f"<td><code>{escape(endpoint.normalized_path)}</code><br><span class=\"meta\">Raw variants: {len(endpoint.raw_paths or [endpoint.raw_path])}</span></td>"
        f'<td><span class="score {severity}">{endpoint.risk_score}</span><br><span class="meta">{escape(severity)}</span></td>'
        f"<td>{escape(endpoint.extraction_confidence)}</td>"
        f'<td title="{escape(source_title)}">{_pills(sources)}</td>'
        f"<td>{tag_html}</td>"
        f"<td>{reason_html}</td>"
        "</tr>"
    )


def _warnings(result: ScanResult) -> str:
    if not result.warnings:
        return '<p class="empty">No warnings.</p>'
    return "<ul>" + "".join(f"<li>{escape(warning)}</li>" for warning in result.warnings) + "</ul>"


def _count_list(counts: dict, empty: str) -> str:
    if not counts:
        return f'<p class="empty">{escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{escape(str(key))}: {value}</li>" for key, value in counts.items()) + "</ul>"


def _pills(items: list) -> str:
    return "".join(f'<span class="pill">{escape(str(item))}</span>' for item in items)


def _select_options(items) -> str:
    return "".join(
        f'<option value="{escape(str(item), quote=True)}">{escape(str(item))}</option>'
        for item in items
    )


def _finding_draft(finding) -> str:
    evidence = "\n".join(f"- {item}" for item in finding.evidence)
    manual = "\n".join(f"- {item}" for item in finding.manual_check)
    return (
        f"## {finding.endpoint}\n\n"
        f"Type: {finding.type}\n"
        f"Severity: {finding.severity}\n"
        f"Confidence: {finding.confidence}\n\n"
        "### Evidence\n"
        f"{evidence}\n\n"
        "### Manual Test Plan\n"
        f"{manual}\n"
    )
