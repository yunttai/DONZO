#!/usr/bin/env bash
set -euo pipefail

scope="${1:-scope.example.yaml}"
python harness/scripts/validate_scope.py --scope "$scope"
codex exec --full-auto < harness/prompts/recon-plan.md
