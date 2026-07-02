---
name: safe-recon-planner
description: Build scope-bound, low-risk bug bounty recon plans. Use when Codex needs to choose DONZO fast, normal, or deep recon phases, create command plans, or decide which scanners and analyzers are safe to run.
---

# Safe Recon Planner

Plan recon as candidate discovery, not exploitation.

## Workflow

1. Load and validate scope.
2. Choose `fast`, `normal`, or `deep`.
3. Prefer passive collection and low-rate probing.
4. Put risky modules behind explicit policy flags.
5. Add raw output, normalization, dedupe, redaction, and report steps.
6. Include manual verification notes for every candidate-producing phase.

Use `scripts/summarize_scope.py` to summarize a YAML scope file.
Read `references/recon-boundaries.md` before planning deep or scanner-heavy work.
