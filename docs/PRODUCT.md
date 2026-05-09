# Product Direction

RouteHawk is a local-first, scope-safe API reconnaissance workspace that turns noisy endpoint discovery into prioritized, evidence-backed manual security review tasks.

## What It Is

RouteHawk is not an exploit scanner. It is a review workflow for authorized security work:

- collect API surface evidence from multiple passive and low-impact sources
- normalize duplicate routes into a usable endpoint inventory
- classify IDOR, authorization, admin, internal, debug, export, GraphQL, and metadata signals
- generate manual review tasks with evidence and checklists
- preserve run history, diffs, triage state, and reports locally

RouteHawk is not a scanner that "finds vulnerabilities". It organizes endpoint evidence and helps prioritize manual review.

## Primary User Value

When a reviewer has many raw routes, RouteHawk should answer:

- which endpoints are new vs already known
- which routes changed risk or confidence between runs
- why an endpoint is prioritized
- what to test manually next

The product should reduce review noise and increase evidence quality, not increase request aggressiveness.

RouteHawk prioritizes precision over raw endpoint count. It separates security risk signals from app relevance so third-party documentation, repository references, and vendor library strings do not crowd out likely first-party application routes.

RouteHawk is not a vulnerability verifier. It produces endpoint inventory, evidence quality signals, and manual review candidates.

## Differentiation

Existing tools commonly focus on one layer:

- JavaScript endpoint extraction
- crawling and URL discovery
- template-based vulnerability checks
- subdomain or probe imports

RouteHawk should sit after or beside those tools. Its job is to turn their output plus its own collectors into a local review workspace.

## Product UX Priorities

- Fast local setup for a safe demo and repeatable scans
- Clear “does vs does not do” safety messaging
- Endpoint-level compare drilldown for run-to-run changes
- Reports suitable for manual review notes and handoff

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

## Story To Communicate On GitHub

RouteHawk is a local-first endpoint intelligence workspace for authorized security review:

- collect
- normalize
- prioritize
- compare
- document manual review tasks

without crossing into exploitation or destructive behavior.
