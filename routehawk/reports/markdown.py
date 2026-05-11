from __future__ import annotations

from routehawk.core.models import ScanResult
from routehawk.reports.summary import build_summary


def render_markdown(result: ScanResult) -> str:
    summary = build_summary(result)
    coverage = _source_coverage(result)
    lines = [
        "# RouteHawk Report",
        "",
        f"Target: `{result.target}`",
        f"Scope: `{', '.join(result.scope) if result.scope else 'not recorded'}`",
        f"Mode used: `{result.scan_mode}`",
        "",
        "## Executive Summary",
        "",
        f"- Assets discovered: {summary.asset_count}",
        f"- JavaScript files analyzed: {summary.javascript_file_count}",
        f"- Metadata records: {summary.metadata_count}",
        f"- Normalized endpoints: {summary.endpoint_count}",
        f"- Manual test candidates: {summary.finding_count}",
        f"- High-risk routes: {summary.high_risk_count}",
        f"- Medium-risk routes: {summary.medium_risk_count}",
        f"- Warnings: {summary.warning_count}",
        "",
        "## Source Coverage",
        "",
    ]

    lines.extend(_source_coverage_lines(coverage))

    lines.extend(["", "## Endpoint Source Breakdown", ""])
    if summary.source_counts:
        lines.extend(f"- {source}: {count}" for source, count in summary.source_counts.items())
    else:
        lines.append("_No endpoint sources recorded._")

    lines.extend(["", "## Scan Explanation", ""])
    lines.extend(_scan_explanation_lines(result, coverage, summary.high_risk_count))

    lines.extend(["", "## Top Manual Test Candidates", ""])
    if not result.findings:
        lines.append("_No high-risk manual test candidates recorded yet._")
    else:
        for finding in result.findings:
            lines.extend(
                [
                    f"### [{finding.severity.title()}] {finding.endpoint}",
                    "",
                    "Evidence:",
                ]
            )
            lines.extend(f"- {item}" for item in finding.evidence)
            lines.extend(["", "Manual test:"])
            lines.extend(f"- {item}" for item in finding.manual_check)
            lines.append("")

    lines.extend(["## Route Groups", ""])
    if not summary.route_groups:
        lines.append("_No route groups recorded._")
    else:
        for group in summary.route_groups:
            methods = ", ".join(group.methods) if group.methods else "n/a"
            tags = ", ".join(group.tags[:8]) if group.tags else "none"
            lines.append(
                f"- `{group.prefix}` - {group.count} routes - max risk {group.max_risk_score} - methods {methods} - tags {tags}"
            )

    lines.extend(["## Discovered Assets", ""])
    if not result.assets:
        lines.append("_No assets recorded._")
    else:
        for asset in result.assets:
            tech = ", ".join(asset.technologies) if asset.technologies else "unknown"
            lines.append(f"- {asset.scheme}://{asset.host} - {asset.status or 'n/a'} - {asset.title or 'untitled'} - {tech}")

    lines.extend(["", "## JavaScript Files", ""])
    if not result.javascript_files:
        lines.append("_No JavaScript files analyzed._")
    else:
        for item in result.javascript_files:
            lines.append(
                f"- `{item.url}` - {item.size} bytes - {item.endpoints_found} endpoints - sha256 `{item.sha256[:12]}...`"
            )

    lines.extend(["", "## Metadata", ""])
    if not result.metadata:
        lines.append("_No metadata records collected._")
    else:
        for item in result.metadata:
            lines.append(f"- {item.source}: `{item.url}` - status {item.status or 'n/a'} - {item.details}")

    lines.extend(["", "## Endpoint Inventory", ""])
    if not result.endpoints:
        lines.append("_No endpoints recorded yet._")
    else:
        for endpoint in sorted(result.endpoints, key=lambda item: item.risk_score, reverse=True):
            tags = ", ".join(endpoint.tags) if endpoint.tags else "none"
            sources = ", ".join(endpoint.sources or [endpoint.source])
            reasons = endpoint.risk_reasons[:5]
            relevance_reasons = endpoint.relevance_reasons[:3]
            lines.extend(
                [
                    f"### {endpoint.method} `{endpoint.normalized_path}`",
                    "",
                    f"- Risk score: {endpoint.risk_score}",
                    f"- Extraction confidence: {endpoint.extraction_confidence}",
                    f"- App relevance: {endpoint.app_relevance}",
                    f"- Relevance reasons: {', '.join(relevance_reasons) if relevance_reasons else 'none'}",
                    f"- Sources: {sources}",
                    f"- Tags: {tags}",
                    f"- Source URLs: {len(endpoint.source_urls or [endpoint.source_url])}",
                    f"- Risk reasons: {', '.join(reasons) if reasons else 'none'}",
                    "",
                ]
            )

    lines.extend(["## Warnings", ""])
    if not result.warnings:
        lines.append("_No warnings._")
    else:
        lines.extend(f"- {warning}" for warning in result.warnings)

    return "\n".join(lines).rstrip() + "\n"


def _source_coverage(result: ScanResult) -> dict:
    value = result.source_coverage
    return value if isinstance(value, dict) else {}


def _source_coverage_lines(coverage: dict) -> list:
    homepage = _coverage_section(coverage, "homepage")
    javascript = _coverage_section(coverage, "javascript")
    robots = _coverage_section(coverage, "robots")
    sitemap = _coverage_section(coverage, "sitemap")
    security_txt = _coverage_section(coverage, "security_txt")
    openapi = _coverage_section(coverage, "openapi")
    graphql = _coverage_section(coverage, "graphql")
    auth_behavior = _coverage_section(coverage, "auth_behavior")

    lines = [
        f"- Homepage: fetched `{_bool_text(homepage.get('fetched'))}` | status `{_status_text(homepage.get('status'))}`",
        f"- JavaScript: discovered `{_safe_int(javascript.get('discovered'))}` | downloaded `{_safe_int(javascript.get('downloaded'))}` | skipped out-of-scope `{_safe_int(javascript.get('skipped_out_of_scope'))}` | failed `{_safe_int(javascript.get('failed'))}`",
        f"- robots.txt: checked `{_bool_text(robots.get('checked'))}` | status `{_status_text(robots.get('status'))}`",
        f"- sitemap.xml: checked `{_bool_text(sitemap.get('checked'))}` | status `{_status_text(sitemap.get('status'))}`",
        f"- security.txt: checked `{_bool_text(security_txt.get('checked'))}` | status `{_status_text(security_txt.get('status'))}`",
        f"- OpenAPI: checked `{_bool_text(openapi.get('checked'))}` | candidates `{_safe_int(openapi.get('candidates_checked'))}` | found `{_safe_int(openapi.get('found'))}`",
        f"- GraphQL: checked `{_bool_text(graphql.get('checked'))}` | candidates `{_safe_int(graphql.get('candidates_checked'))}` | found `{_safe_int(graphql.get('found'))}`",
        f"- Auth behavior: enabled `{_bool_text(auth_behavior.get('enabled'))}` | probe limit `{_safe_int(auth_behavior.get('probe_limit'))}`",
    ]
    return lines


def _scan_explanation_lines(result: ScanResult, coverage: dict, high_risk_count: int) -> list:
    lines = []
    homepage = _coverage_section(coverage, "homepage")
    javascript = _coverage_section(coverage, "javascript")
    auth_behavior = _coverage_section(coverage, "auth_behavior")
    runtime = _coverage_section(coverage, "runtime")
    found_endpoints = len(result.endpoints)
    findings = len(result.findings)
    discovered = _safe_int(javascript.get("discovered"))
    downloaded = _safe_int(javascript.get("downloaded"))
    skipped = _safe_int(javascript.get("skipped_out_of_scope"))

    lines.append(f"- Scan mode: `{result.scan_mode}`.")
    if homepage.get("fetched"):
        lines.append(f"- Target fetched successfully (status `{_status_text(homepage.get('status'))}`).")
    else:
        lines.append("- Target fetch failed or was not completed.")

    lines.append(f"- `{downloaded}` JavaScript files were downloaded.")
    if discovered == 0:
        lines.append("- No JavaScript assets were discovered on the fetched page.")
    elif discovered > 0 and downloaded == 0:
        lines.append(
            "- JavaScript assets were discovered, but none were downloaded. They may be outside configured scope or unavailable."
        )
    if skipped > 0:
        lines.append(f"- Skipped `{skipped}` JavaScript assets because they were outside configured scope.")

    lines.append(f"- `{found_endpoints}` endpoint candidates were found.")
    lines.append(f"- `{findings}` manual review candidates were generated.")
    if high_risk_count == 0:
        lines.append("- No high-risk candidates were found.")

    if not auth_behavior.get("enabled"):
        lines.append("- Auth behavior checks were disabled.")
    else:
        lines.append(f"- Auth behavior checks were enabled with probe limit `{_safe_int(auth_behavior.get('probe_limit'))}`.")

    budget = _safe_int(runtime.get("request_budget_per_scan"))
    if budget > 0:
        lines.append(f"- Request budget per scan: `{budget}`.")
    if _has_budget_warning(result.warnings):
        lines.append("- Request budget was enabled and the scan stopped early after reaching the budget.")
    else:
        lines.append("- Request budget was enabled.")
    if result.scan_mode == "import-only":
        lines.append("- Import-only mode did not perform live HTTP requests.")
    if result.scan_mode == "passive":
        lines.append("- Passive mode skipped JavaScript downloads and GraphQL candidate probes.")

    for warning in result.warnings:
        text = str(warning)
        if text.startswith("No previous scan found for this target/scope"):
            lines.append(f"- {text}")
            break
    return lines


def _coverage_section(coverage: dict, key: str) -> dict:
    value = coverage.get(key, {})
    return value if isinstance(value, dict) else {}


def _bool_text(value: object) -> str:
    return "yes" if bool(value) else "no"


def _status_text(value: object) -> str:
    try:
        if value is None:
            return "n/a"
        return str(int(value))
    except (TypeError, ValueError):
        return "n/a"


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _has_budget_warning(warnings: list) -> bool:
    return any(
        "Request budget exceeded; scan stopped early." in str(item)
        for item in warnings
    )
