# RouteHawk Roadmap

## v0.1 Current MVP

- Scope-safe CLI
- Local dashboard
- Local demo lab
- JavaScript endpoint extraction
- robots/sitemap/security.txt/OpenAPI/GraphQL collectors
- route normalization and classification
- risk scoring
- interactive HTML report
- finding triage in browser localStorage
- Markdown/JSON export
- scan diff JSON for latest vs previous dashboard run
- dashboard diff panel
- persistent dashboard triage storage
- static asset false-positive suppression
- configurable suppression rules
- dashboard scan loading state
- Docker Compose demo lab
- SQLite scan metadata storage
- SQLite-backed dashboard history
- SQLite-backed result and diff retrieval endpoints
- SQLite-backed HTML/Markdown report regeneration
- Importers: httpx, subfinder, nuclei, nmap
- Security headers and CORS summaries
- Optional auth behavior analyzer
- Demo report artifacts under `examples/`
- Route group summaries

## v0.2 Next

- Persistent scan history and triage state
- Rich scan comparison UI for new, removed, changed endpoints
- More polished dashboard error states
- README screenshots or hosted report preview

## v0.3

- Program/workspace profiles
- Export selected findings as Markdown drafts

## v0.4

- Local FastAPI or richer dashboard backend
- Endpoint group views
- Asset clustering
- Scan comparison UI

## v1.0

- Full local workspace for authorized API security review
- Persistent finding notes
- Evidence attachments
- Report draft generation
- Optional desktop frontend
