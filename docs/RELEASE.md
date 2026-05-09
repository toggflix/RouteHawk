# Release Checklist

## v0.2-alpha Local Validation

Run:

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
py -m routehawk --help
```

## Demo Smoke

Start the local demo target:

```powershell
py labs/demo_server.py
```

In a second terminal:

```powershell
py -m routehawk scan --config config.local-lab.yaml --safe-profile bug-bounty --out results.json
py -m routehawk report --input results.json --out report.md
py -m routehawk report --input results.json --out report.html
```

Confirm:

- `results.json` exists
- `report.md` exists
- `report.html` exists
- report output shows extraction confidence and app relevance
- dashboard compare/filter behavior still works

## Tagging

Do not tag until validation is complete and `main` contains the intended release commit.

Example commands:

```powershell
git tag v0.2.0-alpha
git push origin v0.2.0-alpha
```

This checklist documents the command only; do not create a tag during release-prep tasks unless explicitly requested.

## GitHub Release Notes

Include:

- summary of endpoint precision improvements
- request budget enforcement
- bug bounty safe profile
- app relevance scoring
- dashboard compare/filter improvements
- report formats and local demo instructions
- safety boundaries

## Safety Wording Checklist

Release notes should say:

- authorized security review
- low-impact recon
- endpoint inventory
- manual review guidance
- no exploit automation
- no brute force
- no payload injection
- no auth bypass automation
- no destructive checks

Do not describe RouteHawk as a vulnerability verifier or exploitation tool.

## Screenshots

Do not include screenshots unless real files exist under `docs/screenshots/`.

Do not use fake or placeholder screenshots.
