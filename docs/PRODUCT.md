# Product Direction

RouteHawk is a local-first, scope-safe API reconnaissance workspace that turns noisy endpoint discovery into prioritized, evidence-backed manual security review tasks.

## What It Is

RouteHawk is not an exploit scanner. It is a review workflow for authorized security work:

- collect API surface evidence from multiple passive and low-impact sources
- normalize duplicate routes into a usable endpoint inventory
- classify IDOR, authorization, admin, internal, debug, export, GraphQL, and metadata signals
- generate manual review tasks with evidence and checklists
- preserve run history, diffs, triage state, and reports locally

## Differentiation

Existing tools commonly focus on one layer:

- JavaScript endpoint extraction
- crawling and URL discovery
- template-based vulnerability checks
- subdomain or probe imports

RouteHawk should sit after or beside those tools. Its job is to turn their output plus its own collectors into a local review workspace.

## Non-Goals

- exploit verification automation
- brute force
- login attacks
- payload spraying
- WAF bypass
- destructive checks
- scope-outside crawling

## Near-Term Product Bar

RouteHawk should feel complete when a user can:

- scan an authorized target or safe lab
- review prioritized findings
- mark triage state
- compare scans
- import common recon output
- regenerate old reports from local history
- export clean Markdown/HTML evidence for manual work
