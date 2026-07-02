# DONZO

DONZO is a CLI-first, authorized-only black-box bug bounty automation project.

The project focuses on:

- Scope-safe recon planning
- Artifact parsing and normalization
- Secret redaction
- Vulnerability candidate triage
- Mandatory external LLM tribunal for false-positive reduction
- Evidence-first manual verification reports
- Deterministic harness checks for Codex-assisted development

It does not perform automatic exploitation, automatic bounty submission,
credential attacks, destructive tests, or out-of-scope scanning.

## Quick Start

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python harness/scripts/validate_scope.py --scope scope.example.yaml
python harness/scripts/run_evals.py
python -m pytest
```

## Project Layout

- `AGENTS.md`: Codex operating instructions for this repository.
- `.codex/`: project-local Codex policy, agents, hooks, and command rules.
- `.agents/skills/`: reusable Codex skills for bug bounty automation work.
- `harness/`: deterministic validators, schemas, fixtures, prompts, and evals.
- `src/donzo/`: CLI, scope/policy logic, recon planning, and LLM triage modules.
- `findings/`, `reports/`, `artifacts/`: generated outputs.

## Safety Baseline

All recon and scan work must be authorized and scope-bound. Run scope validation
before any network-facing action:

```bash
python harness/scripts/validate_scope.py --scope scope.example.yaml
```

## Product CLI

```bash
donzo scope validate -c scope.example.yaml
donzo scope check -c scope.example.yaml --target https://api.example.com
donzo plan -c scope.example.yaml -p normal
donzo candidates generate -c scope.example.yaml -i harness/fixtures/sample-artifacts/endpoints.json --allow-external-llm
donzo tribunal run -c scope.example.yaml -i harness/fixtures/sample-artifacts/swagger-finding.json --driver codex_cli --allow-external-llm
donzo report draft -c scope.example.yaml -i harness/fixtures/sample-artifacts/findings.raw.json -o reports/drafts/report.md --allow-external-llm
```

The LLM layer is an adjudication aid. It currently has three explicit call
sites: `candidate_generator`, `finding_triage`, and `report_writer`. Normal
execution is one Codex call per submitted batch or finding, with up to
`llm.drivers.codex_cli.max_attempts` retries for invalid schema output. The
default external LLM driver is `codex_cli`, wrapped by a job workspace, JSON
Schema validator, retry loop, cache, SQLite job log, and audit JSONL. Actual
Codex execution requires `--allow-external-llm`; without that explicit flag,
DONZO fails closed for the item.

If the external LLM call fails, DONZO marks the item
`llm_failed` and excludes it from final ranking/reporting. It does not exploit
targets, validate secrets, or submit reports.
