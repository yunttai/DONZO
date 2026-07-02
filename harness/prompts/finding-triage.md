# Finding Triage Prompt

Triage the provided raw findings into normalized manual-review candidates.

Requirements:

- Validate scope.
- Redact secrets.
- Normalize to `harness/schemas/finding.schema.json`.
- Dedupe repeated findings.
- Do not confirm exploitability.
- Include manual verification steps.
