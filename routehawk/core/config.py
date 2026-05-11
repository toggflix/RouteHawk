from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from routehawk.core.models import (
    RouteHawkConfig,
    RulesConfig,
    ScanOptions,
    ScopeConfig,
    SuppressionConfig,
)
from routehawk.core.scope import normalize_scope_entries


def load_config(path: str) -> RouteHawkConfig:
    data = _load_yaml(path)

    scope_data = data.get("scope", {})
    rules_data = data.get("rules", {})
    scan_data = data.get("scan", {})
    suppression_data = data.get("suppression", {})

    raw_scope_domains = scope_data.get("domains", [])
    if not isinstance(raw_scope_domains, list):
        raw_scope_domains = [str(raw_scope_domains)] if raw_scope_domains else []
    scope_domains, _ = normalize_scope_entries(raw_scope_domains)

    return RouteHawkConfig(
        program=data.get("program", "routehawk-program"),
        scope=ScopeConfig(
            domains=scope_domains,
            cidrs=list(scope_data.get("cidrs", [])),
        ),
        rules=RulesConfig(
            follow_redirects=bool(rules_data.get("follow_redirects", True)),
            reject_out_of_scope_redirects=bool(
                rules_data.get("reject_out_of_scope_redirects", True)
            ),
            max_rps_per_host=int(rules_data.get("max_rps_per_host", 1)),
            max_concurrency=int(rules_data.get("max_concurrency", 2)),
            timeout_seconds=int(rules_data.get("timeout_seconds", 10)),
            user_agent=str(rules_data.get("user_agent", "RouteHawk/0.1")),
            max_retries=int(rules_data.get("max_retries", 1)),
            retry_backoff_seconds=float(rules_data.get("retry_backoff_seconds", 1.0)),
            respect_retry_after=bool(rules_data.get("respect_retry_after", True)),
            request_budget_per_scan=int(rules_data.get("request_budget_per_scan", 500)),
        ),
        scan=ScanOptions(
            passive_first=bool(scan_data.get("passive_first", True)),
            download_javascript=bool(scan_data.get("download_javascript", True)),
            parse_openapi=bool(scan_data.get("parse_openapi", True)),
            parse_robots=bool(scan_data.get("parse_robots", True)),
            parse_sitemap=bool(scan_data.get("parse_sitemap", True)),
            check_common_metadata=bool(scan_data.get("check_common_metadata", True)),
            check_auth_behavior=bool(scan_data.get("check_auth_behavior", False)),
            auth_probe_limit=int(scan_data.get("auth_probe_limit", 0)),
        ),
        suppression=SuppressionConfig(
            ignore_suffixes=list(suppression_data.get("ignore_suffixes", [])),
            ignore_path_prefixes=list(suppression_data.get("ignore_path_prefixes", [])),
            ignore_regexes=list(suppression_data.get("ignore_regexes", [])),
        ),
        targets=list(data.get("targets", [])),
    )


def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to load config files. Run: py -m pip install -e .") from exc

    loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError("Config file must contain a YAML mapping at the top level.")
    return loaded
