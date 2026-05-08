# Changelog

## 0.1.0 - Unreleased

### Added

- Scope-safe Python CLI with `scan`, `extract-js`, `report`, and `serve`.
- Local dashboard with scan form, loading state, latest summary, scan history, and diff panel.
- JavaScript endpoint extraction, route normalization, classification, risk scoring, and manual review findings.
- Collectors for JavaScript assets, robots.txt, sitemap.xml, security.txt, OpenAPI/Swagger, and GraphQL candidate paths.
- Security headers and CORS metadata summaries.
- Optional, disabled-by-default HEAD-based auth behavior probes.
- Route group summaries by normalized endpoint prefix.
- JSON, Markdown, and interactive HTML reports.
- Committed safe demo outputs under `examples/`.
- Persistent dashboard triage in `.routehawk/triage.json`.
- SQLite scan metadata and result/diff storage in `.routehawk/routehawk.sqlite`.
- SQLite-backed dashboard history and report/result/diff retrieval.
- Import parsers for httpx JSON, subfinder JSON/plain lines, nuclei JSON, and nmap XML.
- Safe local demo lab with Python and Docker Compose options.
- Configurable endpoint suppression rules for suffix, path prefix, and regex noise.
- Dashboard scan success/error banners.
- Risk-sorted dashboard diff previews with visible item limits.
- Dashboard run-compare panel for selecting any two historical scans.
- Dashboard compare details table for new/removed/changed endpoint drilldown.
- CLI snapshot diff command: `routehawk compare --base ... --head ...`.
- CLI history command: `routehawk history --workspace ...`.

### Safety

- No exploit automation, brute force, login attacks, payload spraying, or bypass attempts.
- Scope validation is enforced before HTTP requests.
- Optional auth behavior checks use HEAD requests and are disabled by default.
