# Validation Checklist

Required checks:

- Target is in scope.
- Evidence is redacted.
- Source tool or heuristic is recorded.
- Finding is not presented as confirmed unless manually reviewed.
- Reproduction notes do not include exploitation or secret use.
- Manual verification steps are specific and safe.
- Confidence reflects evidence quality.

Common false positives:

- Archived URL no longer live.
- Public config that is intentionally non-secret.
- Login or docs page that is expected public behavior.
- Scanner result with only banner/version evidence.
- Redirect limited to same-origin paths.
