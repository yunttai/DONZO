# Harness Contract

The harness is the deterministic control layer for Codex-assisted security work.

It must:

- reject invalid scope
- reject unsafe scan policy
- validate output schemas
- redact secrets
- normalize severities
- dedupe repeated findings
- produce reviewable JSON and Markdown
- run locally and in CI without live targets

It must not:

- run real recon by default
- require credentials
- validate secrets by calling external APIs
- perform exploit attempts
