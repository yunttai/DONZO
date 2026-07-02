# DONZO Harness

The harness is the deterministic control layer for Codex-assisted security
automation. It validates scope, schemas, redaction, finding normalization,
dedupe, and report generation without touching live targets.

Run:

```bash
python harness/scripts/validate_scope.py --scope scope.example.yaml
python harness/scripts/run_evals.py
```

The harness is intentionally conservative. Live recon belongs behind explicit
scope, rate limits, and user approval.

The harness also validates the mandatory tribunal fail-closed path. Test runs do
not call external LLMs; they assert that missing external verdicts become
`llm_failed` and are excluded from final reports. Production LLM drivers must use
explicit configuration and schema-constrained output validation.
