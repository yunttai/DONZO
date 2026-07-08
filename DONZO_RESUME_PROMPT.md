# DONZO Resume Prompt

Continue implementing DONZO using `DONZO_ROADMAP.md` and
`DONZO_CHECKLIST.json` as source of truth.

Current completion: 100.0% baseline and 100.0% refinement backlog.

Current state:

1. All checklist items in `DONZO_CHECKLIST.json` are `done`.
2. All refinement backlog items in `DONZO_CHECKLIST.json.refinement_backlog`
   are `done`.
3. The roadmap artifacts are implemented and wired through CLI/pipeline where
   applicable.
4. Full validation passed:
   - `python -m pytest -q` -> 136 passed
   - `python harness/scripts/run_evals.py` -> passed

If continuing work, use this prompt to start the next product iteration:

1. Inspect `git status --short`.
2. Review the roadmap artifacts:
   - `api-artifact-index.json`
   - `ui-field-usage.jsonl`
   - `actors.jsonl`
   - `actor-relationships.jsonl`
   - `flow-manifest.jsonl`
   - `graphql-operations.jsonl`
   - `graphql-logical-endpoints.jsonl`
   - `business-flows.jsonl`
   - `business-state-invariants.jsonl`
   - `business-mutation-plans.jsonl`
   - `feedback-graph.json`
   - `websocket-messages.jsonl`
   - `sse-events.jsonl`
   - `realtime-logical-endpoints.jsonl`
   - `agent-interfaces.json`
   - `agent-runs.jsonl`
   - `llm-agent-outputs.jsonl`
   - `oracle-results.jsonl`
   - `report-drafts.jsonl`
   - `regression-cases.jsonl`
3. Add only scoped, non-destructive improvements with tests.

Completed refinement priority order:

1. `R-P0-ACTOR-ACCOUNT-MODEL`
2. `R-P0-TRAFFIC-FLOW-METADATA`
3. `R-P1-HAR-CAPTURE-WIZARD`
4. `R-P1-GRAPHQL-OPERATION-MODEL`
5. `R-P1-BUSINESS-LOGIC-MODEL`
6. `R-P1-MANUAL-FEEDBACK-GRAPH`
7. `R-P2-WEBSOCKET-SSE-MODEL`
8. `R-P3-ACTUAL-LLM-MULTI-AGENT-CALLS`

Use `DONZO_CHECKLIST.json.refinement_backlog` as the source of truth for these
refinements. Deterministic models and redaction contracts are implemented
ahead of live LLM calls. External LLM calls remain optional/fail-closed.

Safety boundary:

- Keep all tests offline and deterministic.
- Do not add automatic exploitation, destructive testing, DoS, enumeration, or
  secret validation.
- Generated test plans must remain safe manual verification recipes.

Known current validation:

- `python -m pytest -q` passed with 136 tests.
- `python harness/scripts/run_evals.py` passed.
- New refinement modules and tests pass targeted `python -m ruff check`.
- Whole-repo `python -m ruff check src tests` still reports pre-existing lint
  debt in older files.
