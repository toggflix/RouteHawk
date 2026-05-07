# RouteHawk

RouteHawk is a scope-safe API and JavaScript reconnaissance assistant for authorized bug bounty workflows.

It extracts endpoints from JavaScript bundles, OpenAPI documents, robots.txt, sitemap.xml and common metadata files, normalizes discovered routes, classifies risky API patterns, and generates manual testing checklists for authorization, IDOR, admin/internal/debug exposure and API surface review.

RouteHawk does not exploit vulnerabilities, brute-force targets, or perform payload injection. It focuses on evidence collection, prioritization, and manual testing guidance.

## Current status

This repository contains a working v0.1 local product:

- Scope-safe CLI and local dashboard
- JavaScript, robots.txt, sitemap.xml, security.txt, OpenAPI, and GraphQL candidate collection
- Endpoint normalization, classification, risk scoring, and manual review checklist generation
- Interactive HTML, Markdown, and JSON reports
- Dashboard scan history, diff view, and persistent triage
- SQLite-backed run storage and historical report regeneration
- Import parsers for httpx, subfinder, nuclei, and nmap outputs
- Safe demo lab with Python and Docker Compose options

## Quick start

```powershell
py -m routehawk --help
py -m routehawk scan --config config.example.yaml
py -m unittest discover -s tests
```

After installing the package in editable mode:

```powershell
py -m pip install -e .
routehawk --help
```

## Local demo lab

Start the safe local demo API:

```powershell
py labs/demo_server.py
```

Docker alternative:

```powershell
cd labs
docker compose up --build
```

Then scan it from a second terminal:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out report.html
```

The generated report highlights IDOR/authz/admin/internal/debug candidates from JavaScript, robots.txt, sitemap.xml, and OpenAPI evidence.

## Local dashboard

Run RouteHawk as a local product-style dashboard:

```powershell
py -m routehawk serve --host 127.0.0.1 --port 8090 --workspace .
```

Open:

```text
http://127.0.0.1:8090
```

From the dashboard you can enter an authorized target and scope, run a scan, and open the latest HTML, Markdown, or JSON outputs.

Each dashboard scan also compares the current endpoint inventory with the previous latest run and writes:

```text
http://127.0.0.1:8090/diff/latest.json
```

This highlights new endpoints, removed endpoints, and routes whose risk score changed.

Dashboard-generated reports also persist finding review status locally in `.routehawk/triage.json`, so Interesting/Reviewed/Ignored choices survive browser refreshes and new dashboard sessions.

Endpoint extraction includes built-in static asset suppression and optional config-driven noise rules:

```yaml
suppression:
  ignore_suffixes:
    - ".bak"
  ignore_path_prefixes:
    - "/noise/"
  ignore_regexes:
    - "/api/internal/cache/\\d+"
```

PowerShell shortcut:

```powershell
.\run_dashboard.ps1
```

You can also keep the raw structured result and render reports later:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.md
py -m routehawk report --input results.json --out report.html
```

Import supported external recon output:

```powershell
py -m routehawk import-file --type httpx --input httpx.jsonl --out imported-httpx.json
py -m routehawk import-file --type subfinder --input subfinder.jsonl --out imported-subfinder.json
py -m routehawk import-file --type nuclei --input nuclei.jsonl --out imported-nuclei.json
py -m routehawk import-file --type nmap --input nmap.xml --out imported-nmap.json
```

RouteHawk merges duplicate normalized routes across sources. For example, a billing endpoint found in JavaScript, sitemap.xml, and OpenAPI is reported once with combined evidence and source coverage.

Current reports also include:

- JavaScript files analyzed with SHA-256 hashes and endpoint counts
- Metadata records from robots.txt, sitemap.xml, security.txt, OpenAPI, and GraphQL probes
- Security header and CORS summaries
- Finding-specific manual checklists for IDOR, admin/authz, internal/debug, and GraphQL candidates

Optional auth behavior probes can be enabled in config. They use limited HEAD requests and are disabled by default.

## Project memory

Development state is tracked in:

- `PROJECT_STATE.md`
- `docs/ROADMAP.md`
- `docs/DECISIONS.md`
- `docs/USAGE.md`
- `docs/RELEASE_CHECKLIST.md`

If context is lost in a long session, read `PROJECT_STATE.md` first and continue from the next-improvements section.

## Example

```powershell
routehawk scan --target https://app.example.com --scope "*.example.com" --out report.html
```

## Safety model

RouteHawk is designed around scope safety:

- Exact domains are allowed only when explicitly configured.
- Wildcards match subdomains without matching deceptive suffixes.
- Out-of-scope redirects are rejected by default.
- IP scanning is denied unless IP/CIDR support is explicitly configured later.
