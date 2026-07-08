# DONZO Blackbox API Modeling Roadmap

DONZO's target state is a deterministic, authorized-only Blackbox API Server
Modeler + Vulnerability Reasoning Planner.

It must transform scoped endpoints, HAR traffic, static API hints, schemas, and
manual oracle results into:

- unified endpoint models
- request and response schema models
- parameter and field semantic classifications
- dependency graphs and observed sequences
- backend handler hypotheses
- security invariants
- safe manual test plans
- oracle verdicts
- report drafts and regression cases

DONZO must not perform automatic exploitation, destructive testing, DoS, mass
enumeration, credential attacks, secret validation, or out-of-scope actions.

## Completion

- Current completion: 100.0%
- Source of truth: `DONZO_CHECKLIST.json`
- Progress log: `DONZO_PROGRESS.md`
- Resume prompt: `DONZO_RESUME_PROMPT.md`

## Weighted Milestones

- Phase 0: Unified API data model and artifact structure - 8%
- Phase 1: HAR / traffic ingest - 12%
- Phase 2: Request / response schema inference - 12%
- Phase 3: Parameter / field classifier - 10%
- Phase 4: Dependency graph and sequence model - 14%
- Phase 5: Backend handler hypothesis - 12%
- Phase 6: Security invariant generation - 12%
- Phase 7: Safe manual test plan generation - 10%
- Phase 8: Oracle result model - 6%
- Phase 9: LLM multi-agent / structured triage integration - 3%
- Phase 10: Report draft and regression case generation - 1%

## Completed High-Priority Work

1. Added artifact index and compatibility model modules.
2. Added field semantic wrappers and sequence model wrappers expected by roadmap.
3. Added full oracle result model and evaluator.
4. Added report draft and regression case generation from confirmed oracle results.
5. Added structured LLM agent output schema scaffolding and validation.
6. Wired new artifacts into CLI, pipeline, dashboard, and tests.
7. Completed the refinement backlog: actor/account model, flow metadata,
   HAR capture wizard, GraphQL operation modeling, business-flow modeling,
   manual feedback graph, WebSocket/SSE modeling, and deterministic agent
   interfaces.

## Completed Refinement Roadmap

The current DONZO checklist is complete for both the implemented baseline and
the refinement backlog tracked under `refinement_backlog` in
`DONZO_CHECKLIST.json`.

### Priority Judgement

- P0: Actor/account context and traffic flow metadata come first. Without A/B
  actors plus flow/role/tenant/state labels, tenant, ownership, and role
  invariants stay too generic.
- P1: HAR capture, GraphQL, business logic, and manual feedback deepen the
  model while keeping execution human-controlled and non-destructive. HAR
  capture should follow the P0 metadata contract so captured traffic is useful
  immediately.
- P2: WebSocket/SSE should wait until REST and GraphQL modeling contracts are
  stable because realtime messages reuse the same actor, schema, and invariant
  concepts but add protocol complexity.
- P3: Actual LLM multi-agent calls should be last. Deterministic schemas,
  evidence links, redaction, and rule-based implementations must constrain LLM
  output before external calls become useful.

### Recommended Order

1. P0 - A/B actor and account model.
   - Model `user_A`, `user_B`, `admin`, `member`, `other_org_user`, and
     `anonymous` when available.
   - Represent role, tenant, owned resources, actor relationships, and safe
     credential references.
   - Feed actor context into invariant and safe manual test plan generation.
   - Status: done.

2. P0 - traffic.jsonl actor/state/flow metadata contract.
   - Preserve actor, role, tenant, state, flow, step, and label when supplied.
   - Carry flow metadata into request/response schema records and endpoint
     `source_context`.
   - Validate metadata against the actor/account model when available.
   - Never persist raw credentials, cookies, tokens, localStorage, or
     sessionStorage values.
   - Status: done.

3. P1 - Playwright/Chrome HAR capture wizard.
   - Record HAR while preserving flow label, actor, role, tenant, and state
     metadata.
   - Save `flow-manifest.jsonl` and `traffic.jsonl`.
   - Redact secrets and never persist raw credentials.
   - Status: done.

4. P1 - GraphQL operation modeling.
   - Model `operationName`, query/mutation/subscription, variables, fields,
     node/edge IDs, and resolver-like resource/action semantics.
   - Treat GraphQL operations as logical endpoints instead of collapsing them
     into `POST /graphql`.
   - Status: done.

5. P1 - Business logic model.
   - Infer invitation, password reset, email verification, checkout/payment,
     coupon, refund, subscription, file sharing, approval workflow, role change,
     and OAuth flows.
   - Generate state-transition invariants and safe manual mutation strategies:
     skip, repeat, reorder, replay, accept-after-revoke, confirm-before-payment,
     and reuse-expired-token.
   - Status: done.

6. P1 - Manual execution feedback graph.
   - Let humans enter observed status, body, state, and read-back results.
   - Use 400/401/403/404/409/422/429/200/201/204 feedback to update dependency
     graph, preconditions, state graph, and oracle confidence.
   - Do not add unsafe live exploitation.
   - Status: done.

7. P2 - WebSocket and SSE modeling.
   - WebSocket: connection URL, auth handshake, message type, payload schema,
     channel/room/project/org IDs, and server push events.
   - SSE: event names, stream scope, response schema, and tenant/data leakage
     candidates.
   - Status: done.

8. P3 - Actual LLM multi-agent calls.
   - Define API Agent, Parameter Agent, Dependency Agent, Handler Agent,
     Invariant Agent, Test Plan Agent, Oracle Agent, and Report Agent as
     structured interfaces.
   - Provide deterministic implementations first where possible.
   - Validate LLM output with JSON schemas, evidence links, and redaction.
   - LLM output must not invent endpoints or fields.
   - Status: done for deterministic interfaces and schema-friendly agent runs;
     external LLM calls remain optional/fail-closed.

## Acceptance Standard

The roadmap reaches 100% only when every item in `DONZO_CHECKLIST.json` is
`done`, has tests or explicit validation evidence, and full local validation
passes. Current validation: `python -m pytest -q` passed with 136 tests and
`python harness/scripts/run_evals.py` passed.
