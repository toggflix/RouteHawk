# RouteHawk Agent Instructions

## Project Summary

RouteHawk is a local-first, scope-safe API reconnaissance and endpoint intelligence workspace for authorized security review and bug bounty learning.

RouteHawk turns noisy endpoint discovery into prioritized, evidence-backed manual review tasks.

## Safety Boundaries

RouteHawk must not become:

- an exploit scanner
- a payload scanner
- a brute-force tool
- an auth bypass automation tool
- a destructive testing tool
- a nuclei clone

Always preserve these rules:

- No exploit automation
- No brute force
- No password guessing
- No payload spraying
- No auth bypass automation
- No destructive checks
- No scope-outside crawling
- No aggressive request behavior
- Only authorized-scope evidence collection, prioritization, low-impact recon, and manual review guidance

If a requested feature violates these boundaries, stop and propose a safer design.

## Development Workflow

For every non-trivial feature, follow this order:

1. Security concept explanation
2. Threat model
3. Manual testing workflow
4. RouteHawk data model impact
5. Algorithm/design
6. Implementation
7. Tests
8. README/docs update
9. Safety/scope considerations

## Branch Rules

Use small branches with narrow scope.

Preferred branch prefixes:

- codex/
- agent/

Examples:

- codex/github-actions-ci
- codex/polite-http-client
- codex/js-extractor-hardening
- codex/endpoint-confidence
- codex/dashboard-readability

Do not combine many unrelated features in one branch.

## File Scope Rule

Before editing, identify the exact files needed.

If the task specifies "Strict file scope", only modify the listed files.

If another file must change, stop and explain why before editing it.

## Required Test Commands

After coding, run:

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
py -m routehawk --help
```
