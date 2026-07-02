# Recon Plan Prompt

Create a scope-bound recon plan for the provided scope file.

Requirements:

- Do not include exploit steps.
- Do not include brute force, DoS, credential attacks, or destructive tests.
- Include raw output paths, normalization, redaction, dedupe, ranking, evidence,
  and report steps.
- Mark risky modules as disabled unless policy explicitly enables them.
- Output JSON with phases, commands, required_scope_checks, and risks.
