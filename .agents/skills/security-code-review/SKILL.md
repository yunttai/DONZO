---
name: security-code-review
description: Review DONZO code for safety, security, and bug bounty policy regressions. Use when Codex reviews pull requests, patches, CLI command execution, parsers, redaction, scope filtering, ranking, or report generation.
---

# Security Code Review

Lead with findings. Prioritize exploitable or policy-breaking issues.

## Checklist

1. Scope cannot be bypassed.
2. Shell commands are argument-list based where possible.
3. Paths are normalized and stay inside intended output directories.
4. Secrets are redacted before reports.
5. Risky tools are off by default.
6. Scanner output is not treated as confirmed.
7. Tests cover safety-critical behavior.

Read `references/secure-review-checklist.md` for detailed review prompts.
