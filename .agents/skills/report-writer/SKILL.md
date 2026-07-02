---
name: report-writer
description: Draft evidence-first bug bounty reports from normalized DONZO findings. Use when Codex creates report.md, manual verification queues, executive summaries, or report quality reviews.
---

# Report Writer

Write reports for human verification and later bounty submission drafting.

## Workflow

1. Read normalized findings and ranked candidates.
2. Verify all evidence paths are local artifacts.
3. Redact secret-like values.
4. State confidence and verification status.
5. Include manual verification steps.
6. Avoid exploit claims that the evidence does not support.

Use `assets/bugbounty-report-template.md` as the report structure.
Read `references/report-quality.md` when reviewing report quality.
