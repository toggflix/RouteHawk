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
The run compare drilldown separates `new`, `removed`, and `changed` endpoints so review queues stay readable.
Changed endpoints include explicit deltas for risk score, extraction confidence, tags, and sources when those values differ between runs.
Changed endpoints also surface source URL count and risk reason previews for quick triage context.

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
JavaScript extraction also applies conservative suppression for third-party library/documentation noise and vendor telemetry-like paths.

## CLI

```powershell
py -m routehawk scan --config config.local-lab.yaml --out results.json
py -m routehawk report --input results.json --out report.html
py -m routehawk report --input results.json --out report.md
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
  max_rps_per_host: 2
  max_concurrency: 20
  max_retries: 2
  retry_backoff_seconds: 0.5
  respect_retry_after: true
```

Compare and history commands:

```powershell
py -m routehawk compare --base previous-results.json --head current-results.json --out diff.md
py -m routehawk history --workspace . --limit 10
```

Latest diff output is most meaningful when comparing scans from the same target and scope.

## Safety Notes

RouteHawk is not an exploit tool or payload scanner. Keep usage within authorized scope, with low-impact request settings and manual review workflow goals.

## Tests

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
```
