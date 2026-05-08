# RouteHawk Examples

These files are generated from the safe local demo lab:

- `demo-results.json` - structured scan output
- `demo-report.md` - Markdown report
- `demo-report.html` - interactive HTML report

Regenerate them with:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out examples\demo-results.json
py -m routehawk report --input examples\demo-results.json --out examples\demo-report.md
py -m routehawk report --input examples\demo-results.json --out examples\demo-report.html
```

Root-level `results.json`, `report.md`, and `report.html` remain ignored because they are local working artifacts.
