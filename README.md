# RouteHawk

RouteHawk is a local-first, scope-safe API reconnaissance workspace that turns noisy endpoint discovery into prioritized, evidence-backed manual review tasks.

## What It Does

- Collects endpoints from JavaScript, OpenAPI, robots.txt, sitemap.xml, security.txt, and metadata sources
- Normalizes and deduplicates routes
- Classifies interesting API patterns
- Scores endpoints with risk reason breakdowns
- Tracks endpoint extraction confidence
- Generates Markdown/HTML/JSON reports
- Provides dashboard history, diff, compare, and triage
- Imports external recon outputs

## What RouteHawk Does Not Do

- No exploitation
- No brute force
- No payload injection
- No auth bypass automation
- No destructive checks
- Not a vulnerability scanner
- Not a nuclei replacement

RouteHawk is designed for authorized, low-impact evidence collection and manual security review guidance.

## Quick Demo

1. Install and start the local demo target:

```powershell
py -m pip install -e .
py labs/demo_server.py
```

2. In a second terminal, run a scan and render reports:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.md
py -m routehawk report --input results.json --out report.html
```

3. Open the generated report and inspect prioritized manual review candidates.

Demo artifacts committed in this repository:

- [`examples/demo-results.json`](examples/demo-results.json)
- [`examples/demo-report.md`](examples/demo-report.md)
- [`examples/demo-report.html`](examples/demo-report.html)

## Dashboard Workflow

Run the local dashboard:

```powershell
py -m routehawk serve --host 127.0.0.1 --port 8090 --workspace .
```

Open: `http://127.0.0.1:8090`

From the dashboard you can:

- run authorized scope-safe scans
- review latest reports (HTML/Markdown/JSON)
- compare historical runs
- triage findings locally

Compare output highlights endpoint-level `new`, `removed`, and `changed` sections with risk/confidence/tag/source deltas.

## Core CLI

```powershell
py -m routehawk --help
py -m routehawk scan --config config.example.yaml --out results.json
py -m routehawk report --input results.json --out report.html
py -m routehawk compare --base previous-results.json --head current-results.json --out diff.md
py -m routehawk history --workspace . --limit 10
```

Import external recon output:

```powershell
py -m routehawk import-file --type httpx --input httpx.jsonl --out imported-httpx.json
py -m routehawk import-file --type subfinder --input subfinder.jsonl --out imported-subfinder.json
py -m routehawk import-file --type nuclei --input nuclei.jsonl --out imported-nuclei.json
py -m routehawk import-file --type nmap --input nmap.xml --out imported-nmap.json
```

## Why It Is Useful

RouteHawk helps move from raw recon noise to manual review decisions:

- one merged endpoint inventory across multiple evidence sources
- explicit confidence and risk reasoning for prioritization
- stable local history for diffs and repeated review cycles
- report formats suitable for notes, collaboration, and handoff

## Scope and Request Safety

RouteHawk enforces a scope-first model:

- explicit scope domains
- out-of-scope redirect rejection
- polite request behavior with configurable concurrency/rate/retry controls

Example request controls:

```yaml
rules:
  max_rps_per_host: 2
  max_concurrency: 20
  max_retries: 2
  retry_backoff_seconds: 0.5
  respect_retry_after: true
```

Optional endpoint suppression rules:

```yaml
suppression:
  ignore_suffixes:
    - ".bak"
  ignore_path_prefixes:
    - "/noise/"
  ignore_regexes:
    - "/api/internal/cache/\\d+"
```

## CI

- `.github/workflows/ci.yml`: unit tests, compile checks, CLI smoke
- `.github/workflows/e2e-smoke.yml`: demo lab scan and report smoke

## Additional Docs

- `docs/PRODUCT.md`
- `docs/USAGE.md`
- `PROJECT_STATE.md`
