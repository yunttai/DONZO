# DONZO Progress Log

## 2026-07-08

Initial source-of-truth files created for the long-horizon implementation pass.

Current evidence:

- HAR ingest, redaction, schema inference, API endpoint modeling, parameter
  classification, schema diff, dependency graph, handler hypotheses, security
  invariants, safe manual test plans, and oracle templates are present.
- Artifact index, traffic model compatibility, UI field usage, field semantics,
  sequence model compatibility, oracle result evaluation, structured LLM agent
  output scaffolding, report drafts, and regression case generation are present.
- `python -m pytest -q` passed with 127 tests.
- `python harness/scripts/run_evals.py` passed.

Current completion: 100.0%

Completed:

- Phase 0 artifact index.
- Phase 1 traffic model compatibility.
- Phase 2 UI field usage artifact.
- Phase 3 field semantics wrapper and missing classes.
- Phase 4 sequence model compatibility and value-match evidence.
- Phase 6 expanded security invariant taxonomy.
- Phase 7 expanded safe manual test plan mapping.
- Phase 8 oracle result model/evaluator.
- Phase 9 structured LLM agent output scaffolding.
- Phase 10 report draft/regression generation.

Validation:

1. `python -m pytest -q`
2. `python harness/scripts/run_evals.py`

Next refinement backlog added:

1. P0 actor/account model.
2. P0 traffic.jsonl actor/state/flow metadata contract.
3. P1 Playwright/Chrome HAR capture wizard.
4. P1 GraphQL operation modeling.
5. P1 business logic model.
6. P1 manual execution feedback graph.
7. P2 WebSocket and SSE modeling.
8. P3 actual LLM multi-agent calls.

Priority judgement:

- Actor context is first because invariant and test-plan quality depends on
  A/B ownership, role, and tenant relationships.
- Traffic flow metadata is P0 because HAR without actor/role/tenant/state/flow
  labels is weak input for dependency, state, and business logic modeling.
- HAR capture improves evidence quality immediately after the actor and traffic
  metadata contracts are defined.
- GraphQL and business logic are the next highest P1 modeling gains.
- Manual feedback should refine graph confidence without adding unsafe live
  exploitation.
- WebSocket/SSE and actual LLM calls are intentionally later.

## 2026-07-08 Refinement Backlog Completion

Implemented the full refinement backlog:

- P0 actor/account model with A/B actors, role, tenant, owned resources,
  relationships, safe credential references, and actor-aware invariants/plans.
- P0 traffic metadata contract for actor, role, tenant, state, flow, and label
  across HAR traffic, schemas, endpoint source_context, and sequences.
- P1 HAR capture wizard command that writes redacted HAR, `flow-manifest.jsonl`,
  `traffic.jsonl`, and schema artifacts.
- P1 GraphQL operation model that treats operations as logical endpoints and
  feeds parameter classification, invariants, manual plans, and LLM context.
- P1 business logic model with safe manual mutation plans for invitation,
  reset/verification, checkout/payment, coupon/refund/subscription, sharing,
  approval, role-change, and OAuth-style flows.
- P1 manual feedback graph for human-entered observations and oracle confidence
  updates without unsafe live exploitation.
- P2 WebSocket/SSE JSON artifact modeling into realtime logical endpoints.
- P3 deterministic API, Parameter, Dependency, Handler, Invariant, Test Plan,
  Oracle, and Report agent interfaces with schema-friendly agent runs.

Validation:

1. `python -m pytest -q` passed with 136 tests.
2. `python harness/scripts/run_evals.py` passed.
3. `python -m ruff check` passed for newly added refinement modules and tests.

Known lint note:

- Whole-repo `python -m ruff check src tests` still reports pre-existing lint
  debt in older files, so it is not yet a clean whole-repo gate.
