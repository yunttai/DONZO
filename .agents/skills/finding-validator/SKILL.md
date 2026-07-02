---
name: finding-validator
description: Normalize, dedupe, and validate bug bounty vulnerability candidates as manual-review findings. Use when Codex triages scanner output, reduces false positives, maps severity, or prepares verification checklists.
---

# Finding Validator

Treat every result as a candidate until a human validates it.

## Workflow

1. Confirm target scope.
2. Redact secrets.
3. Normalize fields to `harness/schemas/finding.schema.json`.
4. Map severity and confidence.
5. Dedupe by target, candidate type, title, and evidence hash.
6. Add manual verification steps.
7. Keep `auto_exploit` false.

Read `references/validation-checklist.md` and `references/severity-mapping.md`
when changing triage logic.
