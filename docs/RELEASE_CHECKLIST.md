# Release Checklist

## Pre-Release

- Run `py -m unittest discover -s tests`.
- Run `py -m compileall routehawk labs`.
- Start the demo lab with `.\run_lab_server.ps1`.
- Start the dashboard with `.\run_dashboard.ps1`.
- Scan `http://localhost:8088` with scope `localhost`.
- Confirm the latest report opens from `/reports/latest.html`.
- Confirm SQLite history links open from `/db/runs/{run_id}/report.html`.
- Confirm JSON and diff retrieval return 200 from `/db/runs/{run_id}/results.json` and `/db/runs/{run_id}/diff.json`.
- Confirm dashboard triage writes `.routehawk/triage.json`.

## Documentation

- Update `README.md` feature list.
- Update `CHANGELOG.md`.
- Update `PROJECT_STATE.md`.
- Add screenshots before public GitHub release.

## Safety Review

- Confirm no exploit payloads, brute force, auth bypass, or destructive behavior were added.
- Confirm optional network probes are documented and disabled by default.
- Confirm examples use the local lab or clearly authorized targets.
