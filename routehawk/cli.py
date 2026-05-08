from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

from routehawk.analyzers.auth_behavior import classify_status_code
from routehawk.analyzers.cors import analyze_cors_headers
from routehawk.analyzers.endpoint_extractor import extract_endpoints
from routehawk.analyzers.idor_candidates import (
    ADMIN_AUTHZ_CHECKLIST,
    GRAPHQL_CHECKLIST,
    INTERNAL_DEBUG_CHECKLIST,
    MANUAL_IDOR_CHECKLIST,
    endpoint_confidence,
    score_endpoint_with_reasons,
    severity_for_score,
)
from routehawk.analyzers.route_classifier import classify_endpoint
from routehawk.analyzers.route_normalizer import normalize_path
from routehawk.analyzers.security_headers import missing_security_headers
from routehawk.analyzers.tech_fingerprint import fingerprint_headers
from routehawk.collectors.html_assets import extract_javascript_assets
from routehawk.collectors.javascript_files import download_javascript
from routehawk.collectors.live_hosts import _extract_title
from routehawk.collectors.openapi import COMMON_OPENAPI_PATHS, endpoints_from_openapi
from routehawk.collectors.graphql import GRAPHQL_CANDIDATE_PATHS, looks_like_graphql_response
from routehawk.collectors.robots import parse_robots_txt
from routehawk.collectors.security_txt import parse_security_txt
from routehawk.collectors.sitemap import parse_sitemap_xml
from routehawk.core.config import load_config
from routehawk.core.diff import build_endpoint_diff
from routehawk.core.http_client import ScopeSafeHttpClient
from routehawk.core.models import (
    Asset,
    Endpoint,
    Finding,
    JavaScriptFile,
    MetadataRecord,
    RulesConfig,
    ScanOptions,
    ScanResult,
    SuppressionConfig,
)
from routehawk.core.scope import ScopeValidator
from routehawk.importers.httpx_json import import_httpx_json
from routehawk.importers.nmap_xml import import_nmap_xml
from routehawk.importers.nuclei_json import import_nuclei_json
from routehawk.importers.subfinder_json import import_subfinder_json
from routehawk.reports.html import render_html
from routehawk.reports.markdown import render_markdown
from routehawk.storage.sqlite import list_scan_records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routehawk",
        description="Scope-safe API and JavaScript reconnaissance assistant.",
    )
    parser.add_argument("--version", action="version", version="RouteHawk 0.1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a scoped reconnaissance scan.")
    scan.add_argument("--target", help="Target URL, for example https://app.example.com")
    scan.add_argument("--scope", action="append", default=[], help="Allowed domain or wildcard scope.")
    scan.add_argument("--config", help="Path to YAML config file.")
    scan.add_argument("--out", help="Report output path. Supports .json, .md, and .html.")

    extract_js = subparsers.add_parser("extract-js", help="Extract endpoints from a local JS file.")
    extract_js.add_argument("file", help="JavaScript file path.")
    extract_js.add_argument("--source-url", default="local-file", help="Source URL label for evidence.")
    extract_js.add_argument("--out", help="Optional JSON output path.")

    report = subparsers.add_parser("report", help="Render a Markdown report from RouteHawk JSON.")
    report.add_argument("--input", required=True, help="RouteHawk JSON results file.")
    report.add_argument("--out", required=True, help="Markdown output path.")

    import_file = subparsers.add_parser("import-file", help="Import output from supported recon tools.")
    import_file.add_argument(
        "--type",
        required=True,
        choices=["httpx", "subfinder", "nuclei", "nmap"],
        help="Importer type.",
    )
    import_file.add_argument("--input", required=True, help="Input file path.")
    import_file.add_argument("--out", help="Optional JSON output path.")

    compare = subparsers.add_parser("compare", help="Compare two RouteHawk result JSON files.")
    compare.add_argument("--base", required=True, help="Base (older) RouteHawk result JSON path.")
    compare.add_argument("--head", required=True, help="Head (newer) RouteHawk result JSON path.")
    compare.add_argument("--out", help="Optional output path. Supports .json and .md.")

    history = subparsers.add_parser("history", help="Show recent RouteHawk scan history.")
    history.add_argument("--workspace", default=".", help="Workspace path containing .routehawk.")
    history.add_argument("--limit", type=int, default=10, help="Maximum number of history rows.")
    history.add_argument("--out", help="Optional JSON output path.")

    serve = subparsers.add_parser("serve", help="Run the local RouteHawk dashboard.")
    serve.add_argument("--host", default="127.0.0.1", help="Dashboard bind host.")
    serve.add_argument("--port", type=int, default=8090, help="Dashboard port.")
    serve.add_argument("--workspace", default=".", help="Workspace directory for latest reports.")

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "scan":
        return _scan(args)
    if args.command == "extract-js":
        return _extract_js(args)
    if args.command == "report":
        return _report(args)
    if args.command == "import-file":
        return _import_file(args)
    if args.command == "compare":
        return _compare(args)
    if args.command == "history":
        return _history(args)
    if args.command == "serve":
        return _serve(args)

    parser.error(f"Unknown command: {args.command}")
    return 2


def _scan(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else None
    target = args.target or (config.targets[0] if config and config.targets else None)
    if not target:
        raise SystemExit("scan requires --target or a config file with scan target support")

    scope_domains = list(args.scope)
    if config:
        scope_domains.extend(config.scope.domains)

    scope_cidrs = config.scope.cidrs if config else []
    validator = ScopeValidator(scope_domains, scope_cidrs)
    if not validator.is_url_allowed(target):
        raise SystemExit(f"Target is out of scope: {target}")

    result = asyncio.run(_run_scan(target, sorted(set(scope_domains)), validator, config))
    output = _result_to_json(result)

    if args.out:
        path = Path(args.out)
        if path.suffix.lower() == ".md":
            path.write_text(render_markdown(result), encoding="utf-8")
        elif path.suffix.lower() == ".html":
            path.write_text(render_html(result), encoding="utf-8")
        else:
            path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    else:
        print(json.dumps(output, indent=2))

    return 0


async def _run_scan(
    target: str,
    scope_domains: list,
    validator: ScopeValidator,
    config,
) -> ScanResult:
    rules = config.rules if config else RulesConfig()
    options = config.scan if config else ScanOptions()
    suppression = config.suppression if config else SuppressionConfig()
    client = ScopeSafeHttpClient(validator, rules)
    result = ScanResult(target=target, scope=scope_domains)
    root_url = _origin(target)

    try:
        html = ""
        try:
            response = await client.get_text(target)
            html = response.text
            parsed = urlparse(response.url)
            result.assets.append(
                Asset(
                    host=parsed.hostname or "",
                    scheme=parsed.scheme,
                    status=response.status_code,
                    title=_extract_title(response.text),
                    technologies=fingerprint_headers(response.headers),
                )
            )
            result.metadata.extend(_header_metadata(response.url, response.status_code, response.headers))
        except Exception as exc:
            result.warnings.append(f"Target fetch failed for {target}: {exc}")
            return result

        if html and options.download_javascript:
            javascript_urls = extract_javascript_assets(target, html, validator)
            for javascript_url in javascript_urls:
                try:
                    cached = await download_javascript(
                        client,
                        javascript_url,
                        Path(".cache") / "javascript",
                    )
                    javascript_text = cached.path.read_text(encoding="utf-8", errors="ignore")
                except Exception as exc:
                    result.warnings.append(f"JavaScript fetch failed for {javascript_url}: {exc}")
                    continue
                endpoints = _endpoints_from_text(javascript_text, "javascript", javascript_url, suppression)
                result.javascript_files.append(
                    JavaScriptFile(
                        url=javascript_url,
                        sha256=cached.sha256,
                        cache_path=str(cached.path),
                        size=cached.size,
                        endpoints_found=len(endpoints),
                    )
                )
                result.endpoints.extend(endpoints)

        if options.parse_robots:
            await _collect_robots(client, root_url, result, validator, suppression)
        if options.parse_sitemap:
            await _collect_sitemap(client, root_url, result, validator, suppression)
        if options.parse_openapi:
            await _collect_openapi(client, root_url, result)
        if options.check_common_metadata:
            await _collect_security_txt(client, root_url, result)
            await _collect_graphql(client, root_url, result, suppression)

        result.endpoints = _dedupe_endpoints(result.endpoints)
        if options.check_auth_behavior:
            await _collect_auth_behavior(client, root_url, result, options.auth_probe_limit)
        result.findings = _findings_from_endpoints(target, result.endpoints)
        return result
    finally:
        await client.aclose()


async def _collect_robots(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
    validator: ScopeValidator,
    suppression: SuppressionConfig,
) -> None:
    robots_url = urljoin(root_url, "/robots.txt")
    try:
        response = await client.get_text(robots_url)
    except Exception as exc:
        result.warnings.append(f"robots.txt fetch failed for {robots_url}: {exc}")
        return
    if response.status_code >= 400:
        return
    paths = parse_robots_txt(response.text)
    result.metadata.append(
        MetadataRecord(
            source="robots",
            url=robots_url,
            status=response.status_code,
            details={"entries": len(paths)},
        )
    )
    for item in paths:
        candidate = item if item.startswith(("http://", "https://")) else urljoin(root_url, item)
        if validator.is_url_allowed(candidate):
            result.endpoints.extend(_endpoints_from_text(candidate, "robots", robots_url, suppression))


async def _collect_sitemap(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
    validator: ScopeValidator,
    suppression: SuppressionConfig,
) -> None:
    sitemap_url = urljoin(root_url, "/sitemap.xml")
    try:
        response = await client.get_text(sitemap_url)
    except Exception as exc:
        result.warnings.append(f"sitemap.xml fetch failed for {sitemap_url}: {exc}")
        return
    if response.status_code >= 400:
        return
    try:
        urls = parse_sitemap_xml(response.text)
    except Exception as exc:
        result.warnings.append(f"sitemap.xml parse failed for {sitemap_url}: {exc}")
        return
    result.metadata.append(
        MetadataRecord(
            source="sitemap",
            url=sitemap_url,
            status=response.status_code,
            details={"urls": len(urls)},
        )
    )
    for url in urls:
        if validator.is_url_allowed(url):
            result.endpoints.extend(_endpoints_from_text(url, "sitemap", sitemap_url, suppression))


async def _collect_openapi(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
) -> None:
    for path in COMMON_OPENAPI_PATHS:
        spec_url = urljoin(root_url, path)
        try:
            response = await client.get_text(spec_url)
        except Exception as exc:
            result.warnings.append(f"OpenAPI fetch failed for {spec_url}: {exc}")
            continue
        if response.status_code >= 400:
            continue
        try:
            spec = json.loads(response.text)
        except json.JSONDecodeError:
            continue
        endpoints = endpoints_from_openapi(spec, response.url)
        result.metadata.append(
            MetadataRecord(
                source="openapi",
                url=response.url,
                status=response.status_code,
                details={"paths": len(spec.get("paths", {})) if isinstance(spec.get("paths"), dict) else 0},
            )
        )
        result.endpoints.extend(endpoints)


async def _collect_security_txt(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
) -> None:
    security_url = urljoin(root_url, "/.well-known/security.txt")
    try:
        response = await client.get_text(security_url)
    except Exception as exc:
        result.warnings.append(f"security.txt fetch failed for {security_url}: {exc}")
        return
    if response.status_code >= 400:
        return
    fields = parse_security_txt(response.text)
    result.metadata.append(
        MetadataRecord(
            source="security.txt",
            url=security_url,
            status=response.status_code,
            details={
                "fields": sorted(fields.keys()),
                "contact_count": len(fields.get("contact", [])),
            },
        )
    )


async def _collect_graphql(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
    suppression: SuppressionConfig,
) -> None:
    for path in GRAPHQL_CANDIDATE_PATHS:
        url = urljoin(root_url, path)
        get_status = None
        post_status = None
        response_hint = False

        try:
            get_response = await client.get_text(url)
            get_status = get_response.status_code
            response_hint = response_hint or looks_like_graphql_response(get_response.text)
        except Exception as exc:
            result.warnings.append(f"GraphQL GET probe failed for {url}: {exc}")

        try:
            post_response = await client.post_text(url, "{}")
            post_status = post_response.status_code
            response_hint = response_hint or looks_like_graphql_response(post_response.text)
        except Exception as exc:
            result.warnings.append(f"GraphQL POST probe failed for {url}: {exc}")

        if _looks_like_existing_graphql(get_status, post_status, response_hint):
            result.metadata.append(
                MetadataRecord(
                    source="graphql",
                    url=url,
                    status=post_status or get_status,
                    details={
                        "get_status": get_status,
                        "post_status": post_status,
                        "graphql_response_hint": response_hint,
                    },
                )
            )
            result.endpoints.extend(_endpoints_from_text(path, "graphql", url, suppression))


def _looks_like_existing_graphql(get_status, post_status, response_hint: bool) -> bool:
    interesting = {200, 400, 401, 403, 405}
    return response_hint or get_status in interesting or post_status in interesting


def _header_metadata(url: str, status_code: int, headers) -> list:
    header_dict = dict(headers)
    return [
        MetadataRecord(
            source="security_headers",
            url=url,
            status=status_code,
            details={"missing": missing_security_headers(header_dict)},
        ),
        MetadataRecord(
            source="cors",
            url=url,
            status=status_code,
            details={"signals": analyze_cors_headers(header_dict)},
        ),
    ]


async def _collect_auth_behavior(
    client: ScopeSafeHttpClient,
    root_url: str,
    result: ScanResult,
    limit: int,
) -> None:
    for endpoint in result.endpoints[: max(0, limit)]:
        raw_path = (endpoint.raw_paths or [endpoint.raw_path])[0]
        url = urljoin(root_url, raw_path)
        try:
            response = await client.request_text("HEAD", url)
        except Exception as exc:
            result.warnings.append(f"Auth behavior HEAD probe failed for {url}: {exc}")
            continue
        result.metadata.append(
            MetadataRecord(
                source="auth_behavior",
                url=url,
                status=response.status_code,
                details={
                    "endpoint": f"{endpoint.method} {endpoint.normalized_path}",
                    "probe_method": "HEAD",
                    "behavior": classify_status_code(response.status_code),
                },
            )
        )


def _endpoints_from_text(
    text: str,
    source: str,
    source_url: str,
    suppression: Optional[SuppressionConfig] = None,
) -> list:
    endpoints = []
    for raw in extract_endpoints(text, suppression):
        endpoints.append(
            _endpoint_from_extracted(
                raw.method,
                raw.path,
                raw.parameters,
                source,
                source_url,
                confidence=raw.confidence,
            )
        )
    return endpoints



def _endpoint_from_extracted(
    method: str,
    raw_path: str,
    parameters: list,
    source: str,
    source_url: str,
    confidence: str = "medium",
) -> Endpoint:
    normalized = normalize_path(raw_path)
    tags = classify_endpoint(method, normalized)
    risk_score, risk_reasons = score_endpoint_with_reasons(method, normalized, tags, source=source)
    return Endpoint(
        source=source,
        source_url=source_url,
        method=method,
        raw_path=raw_path,
        normalized_path=normalized,
        parameters=parameters,
        tags=tags,
        extraction_confidence=_normalize_extraction_confidence(confidence),
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        confidence="low",
        sources=[source],
        source_urls=[source_url],
        raw_paths=[raw_path],
    )


def _dedupe_endpoints(endpoints: list) -> list:
    seen = {}
    for endpoint in endpoints:
        key = (endpoint.method, endpoint.normalized_path)
        existing = seen.get(key)
        _ensure_endpoint_lists(endpoint)
        if existing is None:
            seen[key] = endpoint
            continue

        existing.sources = sorted(set(existing.sources + endpoint.sources))
        existing.source_urls = sorted(set(existing.source_urls + endpoint.source_urls))
        existing.raw_paths = sorted(set(existing.raw_paths + endpoint.raw_paths))
        existing.parameters = sorted(set(existing.parameters + endpoint.parameters))
        existing.tags = sorted(set(existing.tags + endpoint.tags))
        existing.risk_reasons = sorted(set(existing.risk_reasons + endpoint.risk_reasons))
        existing.extraction_confidence = _max_extraction_confidence(
            existing.extraction_confidence,
            endpoint.extraction_confidence,
        )
        if endpoint.risk_score > existing.risk_score:
            existing.source = endpoint.source
            existing.source_url = endpoint.source_url
            existing.raw_path = endpoint.raw_path
            existing.risk_score = endpoint.risk_score

    for endpoint in seen.values():
        endpoint.confidence = endpoint_confidence(
            sources=endpoint.sources,
            source_url_count=len(endpoint.source_urls),
            raw_path_count=len(endpoint.raw_paths),
            parameter_count=len(endpoint.parameters),
        )
        if not endpoint.risk_reasons:
            score, reasons = score_endpoint_with_reasons(
                endpoint.method,
                endpoint.normalized_path,
                endpoint.tags,
                source=endpoint.source,
            )
            endpoint.risk_score = max(endpoint.risk_score, score)
            endpoint.risk_reasons = reasons
        endpoint.evidence = _endpoint_evidence(endpoint)
    return sorted(seen.values(), key=lambda item: (item.risk_score, item.normalized_path), reverse=True)


def _findings_from_endpoints(target: str, endpoints: list) -> list:
    findings = []
    for endpoint in endpoints:
        if not _should_create_finding(endpoint):
            continue
        evidence = list(endpoint.evidence)
        findings.append(
            Finding(
                type=_finding_type(endpoint),
                severity=severity_for_score(endpoint.risk_score),
                target=target,
                endpoint=f"{endpoint.method} {endpoint.normalized_path}",
                evidence=evidence,
                manual_check=_manual_check_for_endpoint(endpoint),
                confidence=endpoint.confidence,
            )
        )
    return findings


def _should_create_finding(endpoint: Endpoint) -> bool:
    tags = set(endpoint.tags)
    if endpoint.risk_score >= 56:
        return True
    if tags.intersection({"admin", "internal", "debug", "graphql", "authorization", "data-export"}):
        return endpoint.risk_score >= 35
    return False


def _finding_type(endpoint: Endpoint) -> str:
    tags = set(endpoint.tags)
    if "graphql" in tags:
        return "graphql_candidate"
    if tags.intersection({"internal", "debug"}):
        return "internal_debug_candidate"
    if tags.intersection({"admin", "authorization"}):
        return "admin_authz_candidate"
    if "object-reference" in tags:
        return "idor_candidate"
    return "manual_test_candidate"


def _manual_check_for_endpoint(endpoint: Endpoint) -> list:
    tags = set(endpoint.tags)
    if "graphql" in tags:
        return GRAPHQL_CHECKLIST
    if tags.intersection({"internal", "debug"}):
        return INTERNAL_DEBUG_CHECKLIST
    if tags.intersection({"admin", "authorization"}):
        return ADMIN_AUTHZ_CHECKLIST
    return MANUAL_IDOR_CHECKLIST


def _evidence_from_tags(tags: list) -> list:
    messages = {
        "object-reference": "Contains object identifier pattern",
        "billing": "Billing or payment related path",
        "admin": "Admin-related path",
        "internal": "Internal/private route keyword",
        "debug": "Debug/metrics/config route keyword",
        "authorization": "Roles or permissions related path",
        "data-export": "Export/download related path",
        "user-object": "User/account/customer object keyword",
        "business-object": "Business object keyword",
        "graphql": "GraphQL route keyword",
    }
    return [messages[tag] for tag in tags if tag in messages]


def _ensure_endpoint_lists(endpoint: Endpoint) -> None:
    if not endpoint.sources:
        endpoint.sources = [endpoint.source]
    if not endpoint.source_urls:
        endpoint.source_urls = [endpoint.source_url]
    if not endpoint.raw_paths:
        endpoint.raw_paths = [endpoint.raw_path]


def _endpoint_evidence(endpoint: Endpoint) -> list:
    evidence = []
    for source in endpoint.sources:
        evidence.append(f"Endpoint found in {source}")
    if len(endpoint.source_urls) > 1:
        evidence.append(f"Corroborated by {len(endpoint.source_urls)} source URLs")
    for reason in endpoint.risk_reasons[:4]:
        evidence.append(f"Risk signal: {reason}")
    evidence.extend(_evidence_from_tags(endpoint.tags))
    return sorted(set(evidence))


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_js(args: argparse.Namespace) -> int:
    path = Path(args.file)
    text = path.read_text(encoding="utf-8", errors="ignore")
    endpoints = []

    for raw in extract_endpoints(text):
        normalized = normalize_path(raw.path)
        tags = classify_endpoint(raw.method, normalized)
        score, reasons = score_endpoint_with_reasons(raw.method, normalized, tags, source="javascript")
        endpoint = Endpoint(
            source="javascript",
            source_url=args.source_url,
            method=raw.method,
            raw_path=raw.path,
            normalized_path=normalized,
            parameters=raw.parameters,
            tags=tags,
            extraction_confidence=_normalize_extraction_confidence(raw.confidence),
            risk_score=score,
            risk_reasons=reasons,
            confidence="low",
            sources=["javascript"],
            source_urls=[args.source_url],
            raw_paths=[raw.path],
        )
        endpoints.append(endpoint)

    result = ScanResult(target=args.source_url, scope=[], endpoints=endpoints)
    payload = _result_to_json(result)

    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2))

    return 0


def _report(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    endpoints = [Endpoint(**item) for item in data.get("endpoints", [])]
    assets = [Asset(**item) for item in data.get("assets", [])]
    findings = [Finding(**item) for item in data.get("findings", [])]
    javascript_files = [JavaScriptFile(**item) for item in data.get("javascript_files", [])]
    metadata = [MetadataRecord(**item) for item in data.get("metadata", [])]
    result = ScanResult(
        target=data.get("target", "unknown"),
        scope=data.get("scope", []),
        assets=assets,
        endpoints=endpoints,
        findings=findings,
        javascript_files=javascript_files,
        metadata=metadata,
        warnings=data.get("warnings", []),
    )
    out = Path(args.out)
    if out.suffix.lower() == ".html":
        out.write_text(render_html(result), encoding="utf-8")
    else:
        out.write_text(render_markdown(result), encoding="utf-8")
    return 0


def _import_file(args: argparse.Namespace) -> int:
    text = Path(args.input).read_text(encoding="utf-8", errors="ignore")
    if args.type == "httpx":
        payload = {"assets": [asset.to_dict() for asset in import_httpx_json(text)]}
    elif args.type == "subfinder":
        payload = {"hosts": import_subfinder_json(text)}
    elif args.type == "nuclei":
        payload = {"findings": [finding.to_dict() for finding in import_nuclei_json(text)]}
    elif args.type == "nmap":
        payload = {"assets": [asset.to_dict() for asset in import_nmap_xml(text)]}
    else:
        raise SystemExit(f"Unsupported importer type: {args.type}")

    output = json.dumps(payload, indent=2)
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


def _compare(args: argparse.Namespace) -> int:
    base_payload = _load_result_payload(Path(args.base))
    head_payload = _load_result_payload(Path(args.head))
    diff = build_endpoint_diff(base_payload, head_payload)
    output = {
        "base": str(Path(args.base)),
        "head": str(Path(args.head)),
        "summary": {
            "new_count": diff["new_count"],
            "removed_count": diff["removed_count"],
            "changed_count": diff["changed_count"],
            "unchanged_count": diff["unchanged_count"],
        },
        "diff": diff,
    }
    if args.out:
        path = Path(args.out)
        if path.suffix.lower() == ".md":
            path.write_text(_render_diff_markdown(output), encoding="utf-8")
        else:
            path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    else:
        print(json.dumps(output, indent=2))
    return 0


def _history(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    limit = max(1, int(args.limit))
    records = _history_records(workspace, limit)
    output = {"workspace": str(workspace), "count": len(records), "runs": records}
    if args.out:
        Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")
    else:
        print(_render_history_text(output))
    return 0


def _history_records(workspace: Path, limit: int) -> list:
    routehawk_dir = workspace / ".routehawk"
    database_path = routehawk_dir / "routehawk.sqlite"
    sqlite_records = list_scan_records(database_path, limit=limit)
    if sqlite_records:
        return [
            {
                "source": "sqlite",
                "run_id": item.run_id,
                "generated_at": item.generated_at,
                "target": item.target,
                "scope": item.scope,
                "endpoints": item.endpoint_count,
                "findings": item.finding_count,
                "high_risk": item.high_risk_count,
                "new_endpoints": item.new_endpoint_count,
                "removed_endpoints": item.removed_endpoint_count,
                "changed_endpoints": item.changed_endpoint_count,
            }
            for item in sqlite_records
        ]
    runs_root = routehawk_dir / "runs"
    if not runs_root.exists():
        return []
    records = []
    for run_dir in sorted(runs_root.iterdir(), reverse=True):
        if not run_dir.is_dir() or run_dir.name == "latest":
            continue
        summary_path = run_dir / "summary.json"
        if not summary_path.exists():
            continue
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(summary, dict):
            continue
        records.append(
            {
                "source": "files",
                "run_id": str(summary.get("run_id", run_dir.name)),
                "generated_at": str(summary.get("generated_at", "")),
                "target": str(summary.get("target", "")),
                "scope": summary.get("scope", []) if isinstance(summary.get("scope"), list) else [],
                "endpoints": _safe_int(summary.get("endpoints")),
                "findings": _safe_int(summary.get("findings")),
                "high_risk": _safe_int(summary.get("high_risk")),
                "new_endpoints": _safe_int(summary.get("new_endpoints")),
                "removed_endpoints": _safe_int(summary.get("removed_endpoints")),
                "changed_endpoints": _safe_int(summary.get("changed_endpoints")),
            }
        )
        if len(records) >= limit:
            break
    return records


def _render_history_text(payload: dict) -> str:
    runs = payload.get("runs", [])
    if not isinstance(runs, list):
        runs = []
    lines = [
        "RouteHawk History",
        f"Workspace: {payload.get('workspace', '')}",
        f"Runs: {len(runs)}",
        "",
    ]
    if not runs:
        lines.append("No runs found.")
        return "\n".join(lines)
    for run in runs:
        if not isinstance(run, dict):
            continue
        lines.append(
            " | ".join(
                [
                    str(run.get("run_id", "")),
                    str(run.get("generated_at", "")),
                    str(run.get("target", "")),
                    f"endpoints {run.get('endpoints', 0)}",
                    f"findings {run.get('findings', 0)}",
                    f"high {run.get('high_risk', 0)}",
                    f"+{run.get('new_endpoints', 0)}",
                    f"-{run.get('removed_endpoints', 0)}",
                    f"~{run.get('changed_endpoints', 0)}",
                    f"source {run.get('source', 'unknown')}",
                ]
            )
        )
    return "\n".join(lines)


def _load_result_payload(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON file: {path} ({exc})") from exc
    if not isinstance(loaded, dict):
        raise SystemExit(f"Expected JSON object in file: {path}")
    if not isinstance(loaded.get("endpoints", []), list):
        raise SystemExit(f"Expected endpoints array in file: {path}")
    return loaded


def _render_diff_markdown(payload: dict) -> str:
    diff = payload["diff"]
    lines = [
        "# RouteHawk Diff Report",
        "",
        f"Base: `{payload['base']}`",
        f"Head: `{payload['head']}`",
        "",
        "## Summary",
        "",
        f"- New endpoints: {diff['new_count']}",
        f"- Removed endpoints: {diff['removed_count']}",
        f"- Changed endpoints: {diff['changed_count']}",
        f"- Unchanged endpoints: {diff['unchanged_count']}",
        "",
    ]
    lines.extend(_diff_markdown_section("New endpoints", diff.get("new", [])))
    lines.extend(_diff_markdown_section("Removed endpoints", diff.get("removed", [])))
    lines.extend(_diff_changed_markdown_section(diff.get("changed", [])))
    return "\n".join(lines).rstrip() + "\n"


def _diff_markdown_section(title: str, items: object) -> list:
    rows = [f"## {title}", ""]
    values = items if isinstance(items, list) else []
    if not values:
        rows.append("- None")
        rows.append("")
        return rows
    for item in values:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint", "unknown"))
        risk_score = item.get("risk_score", 0)
        rows.append(f"- `{endpoint}` (risk: {risk_score})")
    rows.append("")
    return rows


def _diff_changed_markdown_section(items: object) -> list:
    rows = ["## Changed endpoints", ""]
    values = items if isinstance(items, list) else []
    if not values:
        rows.append("- None")
        rows.append("")
        return rows
    for item in values:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint", "unknown"))
        previous_score = item.get("previous_risk_score", 0)
        current_score = item.get("current_risk_score", 0)
        rows.append(f"- `{endpoint}` (risk: {previous_score} -> {current_score})")
    rows.append("")
    return rows


def _serve(args: argparse.Namespace) -> int:
    from routehawk.web_app import serve_dashboard

    serve_dashboard(args.host, args.port, Path(args.workspace).resolve())
    return 0


def _result_to_json(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "scope": result.scope,
        "assets": [asset.to_dict() for asset in result.assets],
        "javascript_files": [item.to_dict() for item in result.javascript_files],
        "metadata": [item.to_dict() for item in result.metadata],
        "endpoints": [endpoint.to_dict() for endpoint in result.endpoints],
        "findings": [finding.to_dict() for finding in result.findings],
        "warnings": result.warnings,
    }


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_extraction_confidence(value: str) -> str:
    lowered = (value or "").strip().lower()
    if lowered in {"high", "medium", "low"}:
        return lowered
    return "medium"


def _max_extraction_confidence(left: str, right: str) -> str:
    rank = {"low": 1, "medium": 2, "high": 3}
    normalized_left = _normalize_extraction_confidence(left)
    normalized_right = _normalize_extraction_confidence(right)
    return normalized_left if rank[normalized_left] >= rank[normalized_right] else normalized_right


if __name__ == "__main__":
    raise SystemExit(main())
