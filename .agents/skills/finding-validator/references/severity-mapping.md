# Severity Mapping

Use severity as initial impact, then adjust priority with confidence,
exploitability constraints, data sensitivity, scope, and evidence quality.

Baseline:

- critical: clear sensitive data exposure, account impact, or high-confidence
  takeover candidate.
- high: likely exploitable authorization issue, sensitive API exposure, or
  high-impact misconfiguration.
- medium: exposed admin panels, public API docs with sensitive routes,
  reflected XSS candidates, open redirect candidates.
- low: missing headers, banner disclosure, cookie flags, low-impact metadata.
- info: inventory or weak signal only.

Priority must not exceed evidence. A weak scanner signal should not become P0
without strong correlation.
