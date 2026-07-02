---
name: codex-harness-runner
description: Run and interpret DONZO deterministic harness checks for Codex-assisted work. Use when Codex needs to validate scope files, schemas, redaction, finding normalization, dedupe, report generation, or CI/eval readiness.
---

# Codex Harness Runner

Use deterministic scripts before trusting generated recon or report artifacts.

## Workflow

1. Validate scope.
2. Validate JSON/YAML schemas.
3. Redact candidate outputs.
4. Normalize findings.
5. Dedupe findings.
6. Generate report drafts.
7. Run evals.

Run `scripts/run_harness.py` or `python harness/scripts/run_evals.py`.
Read `references/harness-contract.md` when changing harness behavior.
