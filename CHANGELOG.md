# Changelog

## 0.3.0

- Added deep run support with safe optional tool skip behavior.
- Added review UX artifacts: `review.md`, `review-summary.json`, `review-queue.json`,
  `verification-debug.md`, and `llm-triage-queue.json`.
- Added `donzo review` commands for run summaries, manual review queues, verification
  debug output, and cluster triage queues.
- Added candidate verification/filtering artifacts and cluster evidence pack triage flow.
- Added GitHub Actions CI for lint, tests, scope validation, and harness evals.
- Applied scope `rate_limit` values to supported recon tool command plans.
