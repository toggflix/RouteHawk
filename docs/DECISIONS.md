# RouteHawk Decisions

## Safety

RouteHawk is not an exploit tool. It performs scoped evidence collection, endpoint inventory, classification, and manual review guidance.

No brute force, payload injection, auth bypass attempts, SQLi automation, XSS spam, RCE attempts, or destructive checks should be added to the MVP.

## Product Direction

RouteHawk should differentiate from endpoint extraction and crawling tools by combining:

- scope safety
- evidence merging
- route intelligence
- manual testing guidance
- triage workflow
- local dashboard

## Technical Direction

Language:

- Python for v0.1 through v0.4.

Frontend:

- Static HTML report first.
- Local dashboard uses Python stdlib HTTP server for now.
- Avoid heavy frontend frameworks until the workflow is proven.

Storage:

- Current state is file-based in `.routehawk/runs`.
- SQLite should be added once scan diff and persistent triage are implemented.

