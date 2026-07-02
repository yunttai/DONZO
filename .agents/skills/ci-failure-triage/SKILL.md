---
name: ci-failure-triage
description: Triage DONZO CI failures safely. Use when Codex investigates failing tests, harness checks, schema validation, lint, or GitHub Actions logs without loosening safety policy.
---

# CI Failure Triage

Fix the failing behavior, not the safety gate.

## Workflow

1. Identify the exact failing command.
2. Reproduce locally when possible.
3. Inspect the smallest relevant diff.
4. Preserve scope, redaction, and forbidden-action checks.
5. Add regression coverage if the failure exposed a gap.

Read `references/ci-triage.md` when evaluating a failed pipeline.
