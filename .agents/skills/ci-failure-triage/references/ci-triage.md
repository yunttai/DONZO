# CI Triage

Do not disable failing harness checks unless the check is demonstrably wrong and
a stricter replacement is added.

Common causes:

- invalid YAML or JSON fixture
- schema drift
- missing required finding fields
- unredacted secret-like fixture output
- non-deterministic report timestamps in expected files
- import path changes
