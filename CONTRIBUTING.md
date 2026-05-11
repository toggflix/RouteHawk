# Contributing

Thanks for helping improve RouteHawk.

## Project Goals

RouteHawk is a local-first, scope-safe API reconnaissance and endpoint intelligence workspace. It helps reviewers organize endpoint evidence and prioritize manual review tasks.

## Safety Boundaries

Contributions must preserve these boundaries:

- No exploit automation
- No brute force
- No password guessing
- No payload spraying
- No auth bypass automation
- No destructive checks
- No scope-outside crawling
- No aggressive request behavior

If a feature risks crossing these boundaries, propose a safer design focused on evidence quality, prioritization, or manual review guidance.

## Local Setup

```powershell
py -m pip install -e .
```

Optional local demo:

```powershell
py labs/demo_server.py
```

## Required Validation

Run these before opening a PR:

```powershell
py -m unittest discover -s tests
py -m compileall routehawk labs
py -m routehawk --help
```

## Branch Naming

Use small branches with narrow scope.

Preferred prefixes:

- `codex/`
- `agent/`

## File Scope

Before editing, identify the exact files needed. If an issue or task states a strict file scope, only modify those files. If another file must change, explain why before making the edit.

## PR Expectations

- Keep changes focused.
- Include tests for behavior changes.
- Update docs when user-facing behavior changes.
- Avoid unrelated formatting churn.
- Do not commit generated scan outputs unless they are intentional examples.

## Coding Style

Prefer boring, maintainable, tested code. Use existing project patterns before adding new abstractions.

Documentation language should be English.

Security wording should prefer:

- authorized security review
- scope-safe reconnaissance
- low-impact evidence collection
- endpoint intelligence
- manual review candidate

Avoid wording that suggests exploitation, bypassing, brute forcing, payload injection, or attack automation.
