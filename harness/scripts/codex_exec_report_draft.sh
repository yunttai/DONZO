#!/usr/bin/env bash
set -euo pipefail

python harness/scripts/run_evals.py
codex exec --full-auto < harness/prompts/report-draft.md
