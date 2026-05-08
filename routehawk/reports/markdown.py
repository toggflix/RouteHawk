from __future__ import annotations

from routehawk.core.models import ScanResult
from routehawk.reports.summary import build_summary


def render_markdown(result: ScanResult) -> str:
    summary = build_summary(result)
    lines = [
        "# RouteHawk Report",
        "",
        f"Target: `{result.target}`",
        f"Scope: `{', '.join(result.scope) if result.scope else 'not recorded'}`",
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

    if summary.source_counts:
        lines.extend(f"- {source}: {count}" for source, count in summary.source_counts.items())
    else:
        lines.append("_No endpoint sources recorded._")

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
            lines.extend(
                [
                    f"### {endpoint.method} `{endpoint.normalized_path}`",
                    "",
                    f"- Risk score: {endpoint.risk_score}",
                    f"- Endpoint confidence: {endpoint.confidence}",
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
