---
name: bugbounty-scope
description: Validate and apply authorized bug bounty scope boundaries. Use when Codex plans recon, parses targets, filters findings, checks out-of-scope exclusions, or decides whether a network-facing action is allowed.
---

# Bug Bounty Scope

Use this skill before any recon, scan, parsing, candidate generation, or report
claim that depends on target authorization.

## Workflow

1. Read the scope file and `AGENTS.md`.
2. Confirm `mode: authorized-only`.
3. Verify each target against `in_scope` and `out_of_scope`.
4. Reject forbidden paths and test types before execution.
5. Record removed out-of-scope items separately.
6. Do not infer permission from ownership-like names or public DNS alone.

Read `references/scope-policy.md` when implementing or reviewing scope logic.
