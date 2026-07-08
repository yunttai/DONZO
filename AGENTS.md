# DONZO Agent Instructions

## Mission

DONZO is an authorized-only, CLI-first black-box security validation project.
The tool collects assets, services, endpoints, metadata, vulnerability
candidates, and red-team validation evidence inside explicit scope and ROE,
then prepares evidence, oracle verdicts, reports, and regression cases for a
human tester.

Red-team execution must remain scope-enforced and ROE-bound. This project must
not become an uncontrolled exploit, automatic submission, credential attack,
DoS, destructive testing, or mass attack system.


## Required Workflow

1. Read `scope.example.yaml` or the user-provided scope file.
2. Validate it with `harness/scripts/validate_scope.py`.
3. Apply scope and safety policy before planning any recon.
4. Store raw artifacts under `artifacts/` or `findings/raw/`.
5. Normalize and redact outputs before writing reports.
6. Generate human-verifiable evidence and manual verification steps.
7. For red-team execution, require `scope.yaml`, engagement metadata, actor
   model, rate limits, kill switch, evidence redaction, and per-request Scope
   Guard decisions.
8. Run deterministic harness checks before finalizing changes.

## Local Commands

```bash
python harness/scripts/validate_scope.py --scope scope.example.yaml
python harness/scripts/run_evals.py
python -m pytest
```

Optional formatting/linting:

```bash
python -m ruff check .
```

## Output Contracts

Use JSON/JSONL for machine-readable artifacts and Markdown for human reports.
Expected locations:

- `findings/raw/`
- `findings/normalized/`
- `findings/reviewed/`
- `reports/drafts/`
- `reports/final/`
- `artifacts/codex/`
- `artifacts/recon/`
- `artifacts/evals/`
- `artifacts/logs/`

Every finding-like object should include:

- `finding_id`
- `title`
- `severity`
- `confidence`
- `target`
- `candidate_type`
- `source`
- `evidence`
- `verification_status`
- `auto_exploit: false`

## Code Style

- Prefer small deterministic scripts over prompt-only judgment for validation.
- Keep network-facing behavior behind explicit scope and policy gates.
- Keep parsing tolerant, but output schemas strict.
- Use JSON Schema for artifact validation where possible.
- Keep comments sparse and only where they explain non-obvious safety logic.

## Review Criteria

Security review should prioritize:

- Scope bypasses
- Unsafe command execution
- Secret leakage
- Destructive or high-rate scan paths
- Missing redaction
- Findings presented as confirmed without manual verification
- Missing tests for policy, parser, dedupe, ranking, and report generation

## Definition of Done

- Scope validation passes.
- Harness evals pass.
- Reports are redacted.
- Generated findings remain manual-review candidates.
- Dangerous features are off by default and high-risk probe classes require
  explicit opt-in.
- Tests cover the touched safety-critical behavior.

## CodeGraph

If `.codegraph/` exists, use CodeGraph for structural code questions before
native search. If CodeGraph is not initialized, continue with ordinary file
inspection for scaffolding tasks and ask before initializing a new index.
