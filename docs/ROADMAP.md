# RouteHawk Roadmap

## v0.2-alpha Release Readiness

- Scope-safe CLI and local dashboard
- Local demo lab
- JavaScript endpoint extraction with false-positive suppression
- robots/sitemap/security.txt/OpenAPI/GraphQL collectors
- route normalization and classification
- risk scoring and risk reason breakdowns
- endpoint extraction confidence
- app relevance scoring
- relevance-aware manual candidate generation
- interactive HTML report
- Markdown/JSON export
- dashboard history and compare drilldown
- dashboard endpoint filters for relevance, confidence, source, and manual-candidate status
- request budget enforcement
- bug bounty safe profile
- scan mode presets (passive, bug-bounty-safe, local-lab, import-only, own-app-deep)
- importers: httpx, subfinder, nuclei, nmap
- GitHub Actions CI and local-lab smoke workflows

## High Priority Next

- dashboard filters polish
- first-party vs third-party source classification
- stronger workspace/program profiles
- README/dashboard screenshots from the local demo lab
- v0.2 release packaging

## Medium Priority Next

- Katana importer
- Burp sitemap importer
- Postman collection importer
- finding notes/manual review notes
- coverage/lint CI

## Later

- richer endpoint group views
- asset clustering
- persistent evidence attachments
- report draft generation
- optional desktop frontend

## Non-Goals

- exploit verification automation
- brute force
- payload injection
- auth bypass automation
- destructive checks
- scope-outside crawling
