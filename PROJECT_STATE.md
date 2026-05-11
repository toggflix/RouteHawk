# RouteHawk Project State

Last updated: 2026-05-09

## Project

RouteHawk is a scope-safe API and JavaScript reconnaissance assistant for authorized security review workflows.

It collects endpoint evidence from JavaScript bundles, robots.txt, sitemap.xml, security.txt, OpenAPI/Swagger, and GraphQL candidate paths. It normalizes routes, classifies risk signals, and generates manual review checklists for IDOR, admin/authz, internal/debug, and GraphQL candidates.

RouteHawk does not exploit vulnerabilities, brute-force, spam payloads, bypass authentication, or modify targets. It is evidence collection and manual review guidance only.

## Current Workspace

Project path:

```text
C:\Users\Ahmet\source\repos\RouteHawk
```

Important generated outputs:

```text
C:\Users\Ahmet\source\repos\RouteHawk\results.json
C:\Users\Ahmet\source\repos\RouteHawk\report.md
C:\Users\Ahmet\source\repos\RouteHawk\report.html
C:\Users\Ahmet\source\repos\RouteHawk\.routehawk\runs\latest
C:\Users\Ahmet\source\repos\RouteHawk\.routehawk\runs\latest\diff.json
C:\Users\Ahmet\source\repos\RouteHawk\.routehawk\routehawk.sqlite
```

## Current Ports

- `http://localhost:8088` - safe local demo target
- `http://127.0.0.1:8090` - RouteHawk local dashboard
- `http://127.0.0.1:8090/reports/latest.html` - latest interactive report

## Current Commands

Run tests:

```powershell
py -m unittest discover -s tests
```

Compile check:

```powershell
py -m compileall routehawk labs
```

Run local demo target:

```powershell
.\run_lab_server.ps1
```

Run local dashboard:

```powershell
.\run_dashboard.ps1
```

Manual dashboard command:

```powershell
py -m routehawk serve --host 127.0.0.1 --port 8090 --workspace .
```

Scan local lab with CLI:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.html
py -m routehawk report --input results.json --out report.md
```

Compare two saved scan snapshots:

```powershell
py -m routehawk compare --base previous-results.json --head current-results.json --out diff.json
py -m routehawk compare --base previous-results.json --head current-results.json --out diff.md
```

Show local scan history:

```powershell
py -m routehawk history --workspace . --limit 10
```

## Current Features

CLI:

- `routehawk scan`
- `routehawk extract-js`
- `routehawk report`
- `routehawk import-file`
- `routehawk compare`
- `routehawk history`
- `routehawk serve`

Core:

- YAML config loader
- configurable endpoint suppression rules
- structured data models
- scope validator with exact and wildcard domain handling
- scope-safe async HTTP client
- polite request scheduling (max RPS per host + max concurrency)
- request budget enforcement per scan (`request_budget_per_scan`)
- bounded retries with exponential backoff and optional Retry-After support
- out-of-scope redirect rejection

Collectors:

- HTML JavaScript asset discovery
- JavaScript download/cache with SHA-256
- robots.txt parser
- sitemap.xml parser
- security.txt parser
- OpenAPI/Swagger parser
- GraphQL candidate detection using light GET/POST metadata probes

Analyzers:

- optional disabled-by-default HEAD-based auth behavior classification
- security header and CORS metadata summaries
- route group clustering by normalized endpoint prefix
- regex endpoint extraction
- JavaScript endpoint extractor hardening against function-expression false positives
- static asset and CDN-like false-positive suppression during endpoint extraction
- config-driven suppression for custom suffix, path prefix, and regex noise rules
- route normalization for ids, UUIDs, hashes, tokens, emails, colon params
- route classification tags
- risk scoring
- risk score reason breakdown
- endpoint confidence scoring
- finding generation
- finding-specific manual checklists

Reports:

- JSON output
- Markdown report
- interactive HTML report
- committed demo examples under `examples/`
- route group summary section
- source coverage
- classifier tag summary
- JS file inventory
- metadata inventory
- SQLite-backed historical HTML/Markdown report regeneration
- endpoint inventory
- finding cards
- search and filters
- severity/source/type/status filters
- copy checklist button
- copy finding draft button
- localStorage triage statuses: unreviewed, interesting, reviewed, ignored

Dashboard:

- local web dashboard at port 8090
- target/scope scan form
- scan submit loading state to prevent accidental double submissions
- scan success/error feedback banners from query state
- latest run summary
- latest HTML/Markdown/JSON links
- scan history with timestamped run folders
- scan history backed by SQLite when records are available
- SQLite-backed history JSON and diff retrieval endpoints
- SQLite-backed history HTML and Markdown report regeneration endpoints
- scan diff JSON for new, removed, and changed endpoint risk scores
- dashboard metrics and history links for scan diffs
- dashboard diff panel for new, removed, and changed endpoint summaries
- risk-sorted diff preview with visible item counts
- run compare form for any two historical runs
- run compare detailed endpoint drilldown tables with explicit new/removed/changed sections
- changed endpoint details include risk/confidence/tag/source delta summaries
- dashboard endpoint filters for app relevance, extraction confidence, source, and manual-candidate status
- readability-focused history cards (run id + compact KPI blocks)
- persistent triage storage in `.routehawk\triage.json`
- scan metadata persisted to `.routehawk\routehawk.sqlite`

Docs/demo:

- README product messaging polished around local-first endpoint intelligence and strict safety boundaries
- README quick demo flow now emphasizes safe local lab run and report generation
- docs/USAGE includes quick demo and compare drilldown guidance
- docs/PRODUCT includes user-value framing and GitHub storytelling notes
- examples/README clarifies demo artifact purpose for output shape review
- bug bounty safe usage guidance added across README and docs/USAGE
- optional safe profile and low-impact defaults documented
- request budget enforcement added; budget-exceeded scans return partial results with warning
- third-party JavaScript noise suppression improved for documentation, repository, vendor telemetry, and malformed expression residue
- W3C/documentation suppression refined to avoid suppressing normal locale/XML application routes
- W3C documentation suppression refined to avoid suppressing normal REC/WD-like application routes
- app relevance scoring added to separate target-application likelihood from security risk score
- manual candidate generation is relevance-aware and suppresses low relevance routes
- dashboard and reports now surface app relevance alongside extraction confidence
- v0.2 release-prep docs added: CHANGELOG, SECURITY, CONTRIBUTING, release checklist, screenshot policy

Automation:

- GitHub Actions matrix CI (`.github/workflows/ci.yml`)
- GitHub Actions local-lab smoke run (`.github/workflows/e2e-smoke.yml`)

Demo lab:

- lightweight Python HTTP server at port 8088
- Docker Compose demo lab definition at `labs\docker-compose.yml`
- Docker-compatible lab binding through `ROUTEHAWK_LAB_HOST` and `ROUTEHAWK_LAB_PORT`
- visible demo target page
- embedded JavaScript routes
- robots.txt
- sitemap.xml
- security.txt
- swagger.json
- GraphQL candidate endpoint
- demo API routes for IDOR/admin/internal/debug classification

## Latest Known Verification

Latest test command passed:

```text
93 tests OK
```

Latest compile check passed:

```text
py -m compileall routehawk labs
```

Latest dashboard scan produced:

```text
Assets: 1
JavaScript files: 1
Metadata: 7
Endpoints: 9
Findings: 8
High risk: 4
```

Example findings:

```text
POST /api/admin/users/{id}/role - high - admin_authz_candidate
GET /api/users/{id}/billing - high - idor_candidate
GET /api/users/{id}/profile - high - idor_candidate
GET /api/orders/{id} - high - idor_candidate
GET /internal/metrics - low - internal_debug_candidate
GET /graphql - low - graphql_candidate
GET /debug/config - low - internal_debug_candidate
GET /admin - low - admin_authz_candidate
```

## Similar Tools Observed

High-level positioning from quick GitHub search:

- LinkFinder/xnLinkFinder style tools focus strongly on JavaScript endpoint extraction.
- ProjectDiscovery tools such as katana/httpx/nuclei cover crawling, probing, and template-based scanning.
- RouteHawk should stay differentiated as a scope-safe endpoint intelligence and manual review workflow assistant.

RouteHawk differentiators:

- scope-first safety model
- evidence merging across JS, robots, sitemap, OpenAPI, GraphQL
- manual review checklists instead of exploitation
- interactive report and local dashboard
- finding triage workflow

## Current Known Issues / Next Improvements

High priority:

- dashboard filters polish
- first-party vs third-party source classification
- README/dashboard screenshots
- v0.2 release packaging

Medium priority:

- Katana importer
- Burp sitemap importer
- Postman collection importer
- finding notes/manual review notes
- stronger workspace/program profiles
- coverage/lint CI

Security wording:

- Prefer "authorized security review", "scope-safe reconnaissance", "manual review candidate".
- Avoid product copy that sounds like exploitation, bypassing, brute forcing, payload injection, or attack automation.

## Continuation Instructions For Future Codex Turns

If conversation context is compacted or lost:

1. Read this file first.
2. Run:

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
```

3. Check whether demo/dashboard processes are already listening:

```powershell
Get-NetTCPConnection -LocalPort 8088 -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 8090 -ErrorAction SilentlyContinue
```

4. Continue from the "Current Known Issues / Next Improvements" section.
