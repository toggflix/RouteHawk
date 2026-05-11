# RouteHawk Usage

## Quick Demo

Install RouteHawk locally:

```powershell
py -m pip install -e .
```

Start the safe local demo target:

```powershell
py labs/demo_server.py
```

In a second terminal:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.md
py -m routehawk report --input results.json --out report.html
```

This flow is for local, authorized, low-impact validation of RouteHawk behavior.

## Dashboard

Start the safe demo target:

```powershell
cd C:\Users\Ahmet\source\repos\RouteHawk
.\run_lab_server.ps1
```

Docker alternative:

```powershell
cd C:\Users\Ahmet\source\repos\RouteHawk\labs
docker compose up --build
```

Start the dashboard:

```powershell
.\run_dashboard.ps1
```

Open:

```text
http://127.0.0.1:8090
```

Use:

- Target: `http://localhost:8088`
- Scope: `localhost`

Then open the latest HTML report from the dashboard.

The dashboard also writes a scan diff after each run:

```text
http://127.0.0.1:8090/diff/latest.json
```

Historical runs include their own `diff.json` link in the scan history panel.
The compare panel also supports selecting any two runs and rendering a detailed endpoint-level drilldown.
Latest diff now uses the previous run from the same target/scope fingerprint group only. If no previous run exists for that target/scope, the run is marked as baseline.
If manual compare selects runs with different target/scope fingerprints, the UI shows a warning that counts may be misleading.
The run compare drilldown separates `new`, `removed`, and `changed` endpoints so review queues stay readable.
Changed endpoints include explicit deltas for risk score, extraction confidence, tags, and sources when those values differ between runs.
Changed endpoints also surface source URL count and risk reason previews for quick triage context.

Dashboard endpoint filters can narrow latest diff and compare views by:

- app relevance: all, high, medium, low, or hide low
- extraction confidence: all, high, medium, or low
- source: javascript, openapi, robots, sitemap, graphql, or security.txt
- manual candidates only

Low relevance endpoints are visually muted. Filters are client-side and do not change stored scan results.

Finding review buttons in dashboard-generated reports are persisted locally in:

```text
C:\Users\Ahmet\source\repos\RouteHawk\.routehawk\triage.json
```

Dashboard scan metadata is also recorded in:

```text
C:\Users\Ahmet\source\repos\RouteHawk\.routehawk\routehawk.sqlite
```

The report still keeps a browser-local fallback when opened outside the dashboard.

## Suppression Rules

Use config suppression rules to reduce known endpoint extraction noise:

```yaml
suppression:
  ignore_suffixes:
    - ".bak"
  ignore_path_prefixes:
    - "/noise/"
  ignore_regexes:
    - "/api/internal/cache/\\d+"
```

Built-in suppression already removes common static assets such as images, fonts, CSS, JavaScript maps, and CDN-style `//host/path` strings.

## Endpoint Precision and App Relevance

RouteHawk applies conservative suppression for common third-party JavaScript noise, including documentation/specification paths, repository references, vendor telemetry strings, static assets, and malformed JavaScript expression residue.

Endpoint risk and app relevance are tracked separately:

- Risk score estimates whether an endpoint has security review signals.
- App relevance estimates whether the endpoint appears to belong to the target application.
- Low relevance endpoints may remain in inventory when present in imported data, but they are not promoted as manual review candidates.
- Reviewers should still manually verify scope, ownership, and business relevance before testing.

Reports show app relevance and short relevance reasons next to endpoint confidence so noisy route collections are easier to triage.

## CLI

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.html
py -m routehawk report --input results.json --out report.md
```

For authorized bug bounty workflows, you can apply the built-in low-impact profile:

```powershell
py -m routehawk scan --config config.example.yaml --safe-profile bug-bounty --out results.json
```

Import supported recon output:

```powershell
py -m routehawk import-file --type httpx --input httpx.jsonl --out imported-httpx.json
py -m routehawk import-file --type subfinder --input subfinder.jsonl --out imported-subfinder.json
py -m routehawk import-file --type nuclei --input nuclei.jsonl --out imported-nuclei.json
py -m routehawk import-file --type nmap --input nmap.xml --out imported-nmap.json
```

Optional auth behavior probes are disabled by default. Enable them only for authorized, low-rate review:

```yaml
scan:
  check_auth_behavior: true
  auth_probe_limit: 20
```

Polite client retry/rate settings:

```yaml
rules:
  max_rps_per_host: 1
  max_concurrency: 2
  max_retries: 1
  retry_backoff_seconds: 1.0
  respect_retry_after: true
  request_budget_per_scan: 500
```

Compare and history commands:

```powershell
py -m routehawk compare --base previous-results.json --head current-results.json --out diff.md
py -m routehawk history --workspace . --limit 10
```

Latest diff output is most meaningful when comparing scans from the same target and scope.

Scope inputs are normalized before validation:

- `https://www.whatnot.com` -> `www.whatnot.com`
- `http://localhost:8088/path` -> `localhost:8088`
- `*.example.com` remains `*.example.com`

Normalization notes are included in scan warnings to make scope cleaning explicit.

## Bug Bounty Safe Usage

- Read program scope and rules of engagement before scanning.
- If a program disallows automated scanning, do not run active scans; use local/demo/import workflows only.
- Only scan domains that are explicitly in-scope.
- Do not test third-party infrastructure outside program scope.
- Run login-related checks only when program policy allows it, and only with your own authorized accounts.
- If you encounter sensitive personal, payment, or private data, stop testing and follow the program disclosure process.
- Programs may define stricter request and rate limits; always follow the specific program policy.
- `request_budget_per_scan` sets an upper bound for total scan requests; when exceeded, RouteHawk stops early and returns partial results with a warning.
- Request budgeting does not replace program rate limits or rules; you must still follow the program policy.

Recommended low-impact config:

```yaml
rules:
  max_rps_per_host: 1
  max_concurrency: 2
  max_retries: 1
  retry_backoff_seconds: 1.0
  respect_retry_after: true
  request_budget_per_scan: 500

scan:
  check_auth_behavior: false
  auth_probe_limit: 0
```

## Safety Notes

RouteHawk is not an exploit tool or payload scanner. Keep usage within authorized scope, with low-impact request settings and manual review workflow goals.

## Tests

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
```
