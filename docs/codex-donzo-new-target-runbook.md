# Codex + DONZO New Target Runbook

This runbook is for authorized bug bounty testing only. Keep every run inside
the written scope and ROE. Treat every result as a candidate until it has
redacted evidence and manual verification.

## Operator Inputs

You only need to provide these items:

- Scope and ROE: target URL, allowed domains, out-of-scope paths, forbidden test
  types, rate limits, and whether authenticated testing is authorized.
- Browser login: log in inside the browser window Codex opens. Do not paste
  passwords, cookies, tokens, MFA codes, or session material into chat.
- Test accounts: at minimum two approved same-role accounts with different owned
  data. Example: `user_A` and `user_B`, both student/customer/user, each with
  separate groups, orders, projects, files, assignments, or records.
- Seed data: safe dummy objects for each account. BOLA/IDOR needs real object
  IDs to compare.
- Risk decision: say explicitly whether only read-only GET checks are allowed,
  or whether scoped non-destructive create/update/delete is allowed on dummy test
  data.
- Human-only steps: CAPTCHA, MFA, email verification, account approval, and any
  UI confirmation that cannot be automated safely.

## Hard Stops

Keep these disabled unless the program explicitly authorizes them in writing:

- mass ID enumeration
- destructive mutation
- denial of service
- credential attack
- malware upload
- reverse shell
- sensitive file read
- cloud metadata access without explicit authorization
- third-party data access
- automatic submission
- secret validation

Default to read-only, low-rate, redacted evidence.

## Scope Template

Start from `scope.example.yaml`, then copy to `scope.yaml` and edit only the
target-specific fields:

```yaml
program_name: target-name
profile: deep
mode: authorized-only

in_scope:
  domains:
    - target.example
  urls:
    - https://target.example/app
  ip_ranges: []

out_of_scope:
  domains: []
  urls: []
  paths:
    - /logout
    - /delete
    - /payment
  test_types:
    - dos
    - ddos
    - stress_test
    - bruteforce
    - credential_stuffing
    - destructive_test
    - data_modification
    - automatic_exploit
    - automatic_submission
    - mass_exploitation
    - secret_validation
    - sensitive_file_read
    - third_party_target_testing

scan_policy:
  passive_recon: true
  active_recon: true
  port_scan: false
  crawling: true
  archive_collection: true
  content_discovery: true
  parameter_mining: true
  nuclei_scan: false
  zap_baseline: false
  dalfox_candidate: false
  oast: false
  active_exploit: false
  automatic_submission: false

rate_limit:
  max_requests_per_second: 3
  max_concurrency: 5
  timeout_seconds: 20

verification:
  enabled: true
  fail_closed: true
  network_probe: true
  probe:
    max_requests_per_candidate: 3
    max_network_probes: 0
    allowed_methods:
      - HEAD
      - GET
      - OPTIONS
    allow_post: false
    follow_redirects: true
    max_redirects: 4
    timeout_seconds: 20
    max_body_bytes: 500000
    redact_sensitive_data: true
```

## Commands

Use PowerShell on Windows:

```powershell
python harness/scripts/validate_scope.py --scope scope.yaml
python -m donzo.cli doctor -c scope.yaml --profile deep

$env:DONZO_LONG_RECON="1"
$env:DONZO_KATANA_DEPTH="3"
$env:DONZO_KATANA_CRAWL_DURATION="120"
$env:DONZO_KATANA_MAX_DOMAIN_PAGES="120"

python -m donzo.cli run `
  -c scope.yaml `
  -p deep `
  --execute `
  --llm-triage `
  --llm-limit 0 `
  -o artifacts/<target-slug>/run
```

Use Bash or WSL:

```bash
export DONZO_LONG_RECON=1
export DONZO_KATANA_DEPTH=3
export DONZO_KATANA_CRAWL_DURATION=120
export DONZO_KATANA_MAX_DOMAIN_PAGES=120

python harness/scripts/validate_scope.py --scope scope.yaml
python -m donzo.cli doctor -c scope.yaml --profile deep
python -m donzo.cli run \
  -c scope.yaml \
  -p deep \
  --execute \
  --llm-triage \
  --llm-limit 0 \
  -o artifacts/<target-slug>/run
```

## Authenticated Capture

Capture each actor separately. Codex opens the browser; the operator logs in and
presses Enter in the terminal when the authorized flow is complete.

```powershell
python -m donzo.cli capture-har `
  -c scope.yaml `
  --target https://target.example/app `
  -o artifacts/<target-slug>/manual/userA `
  --actor user_A `
  --role standard_user `
  --tenant tenant_A `
  --state authenticated `
  --flow safe_manual_walkthrough_userA `
  --label userA_safe_manual_walkthrough

python -m donzo.cli capture-har `
  -c scope.yaml `
  --target https://target.example/app `
  -o artifacts/<target-slug>/manual/userB `
  --actor user_B `
  --role standard_user `
  --tenant tenant_B `
  --state authenticated `
  --flow safe_manual_walkthrough_userB `
  --label userB_safe_manual_walkthrough
```

During the browser flow, click normal read workflows first:

- dashboard/home
- profile/account page
- list pages
- object detail pages owned by the account
- files or attachments only if they are dummy test data
- search/filter pages with normal inputs

Avoid submit, delete, payment, approval, invite, password, email, or notification
actions unless explicitly allowed for seeded test data.

## HAR Ingest And Fuzz Planning

Ingest each actor's HAR into structured API artifacts:

```powershell
$O="artifacts/<target-slug>/ingest-userA"
New-Item -ItemType Directory -Force $O | Out-Null

python -m donzo.cli ingest-har `
  -c scope.yaml `
  -i artifacts/<target-slug>/manual/userA/traffic.har `
  --actor user_A `
  --role standard_user `
  --tenant tenant_A `
  --state authenticated `
  --flow safe_manual_walkthrough_userA `
  --label userA_safe_manual_walkthrough `
  --api-endpoints-output "$O/api-endpoints.jsonl" `
  --parameter-classification-output "$O/parameter-classification.jsonl" `
  --schema-diff-output "$O/schema-diff.jsonl" `
  --actors-output "$O/actors.jsonl" `
  --manual-test-plans-output "$O/manual-test-plans.jsonl" `
  --oracle-templates-output "$O/oracle-templates.jsonl" `
  --removed-output "$O/removed.jsonl"

python -m donzo.cli fuzz plan `
  -c scope.yaml `
  --api-endpoints "$O/api-endpoints.jsonl" `
  --parameter-classifications "$O/parameter-classification.jsonl" `
  --schema-diffs "$O/schema-diff.jsonl" `
  --actors "$O/actors.jsonl" `
  -o artifacts/<target-slug>/fuzz-userA
```

`fuzz plan` creates candidates, oracle templates, and safe probe plans. It does
not confirm vulnerabilities by itself.

## Cross-Actor Read-Only Check

For BOLA/IDOR, compare two approved same-role accounts with different owned
objects. Use the helper script to replay a small number of baseline account GET
object URLs in the comparison actor's browser session. The script stores only
status, body digest, length, and schema field names. It does not store raw
response bodies.

```powershell
python scripts\compare-readonly-cross-actor.py `
  -c scope.yaml `
  --target https://target.example/app `
  --baseline-traffic artifacts/<target-slug>/manual/userA/traffic.jsonl `
  --actor user_B `
  -o artifacts/<target-slug>/manual/ab-userB-vs-userA-readonly.jsonl `
  --max-requests 20
```

Interpretation:

- All `403` or `404`: likely blocked for those objects.
- `200` with JSON and sensitive/object fields: needs manual review as possible
  BOLA/IDOR.
- Same data legitimately shared between both accounts: not a finding.
- Different roles or tenants must be documented before claiming impact.

Run the opposite direction too when `user_B` has owned data:

```powershell
python scripts\compare-readonly-cross-actor.py `
  -c scope.yaml `
  --target https://target.example/app `
  --baseline-traffic artifacts/<target-slug>/manual/userB/traffic.jsonl `
  --actor user_A `
  -o artifacts/<target-slug>/manual/ab-userA-vs-userB-readonly.jsonl `
  --max-requests 20
```

## What To Ask Another Codex

Paste this into a fresh Codex thread:

```text
Use the bugbounty-scope, safe-recon-planner, and finding-validator skills.

Goal: run a scope-bound DONZO assessment for a new authorized target.

Rules:
- Read AGENTS.md and scope.yaml first.
- Validate scope before any network action.
- Do not ask me for credentials, cookies, tokens, or secrets.
- Open browser capture flows; I will log in and say "login complete".
- Keep default mode read-only and non-destructive.
- No DoS, brute force, credential attack, destructive mutation, secret
  validation, third-party data access, automatic exploit, or automatic
  submission.
- Redact evidence and treat results as candidates until manually verified.

Target:
- Program: <program name>
- Target URL: <authorized app URL>
- Output slug: <target-slug>
- Accounts available: <user_A/user_B/mentor/admin and what dummy data each owns>
- Allowed mutation level: <read-only only | dummy-data non-destructive mutation allowed>

Tasks:
1. Inspect git status without reverting unrelated changes.
2. Validate scope.yaml.
3. Run DONZO deep recon with safe rate limits.
4. Capture user_A and user_B authenticated HARs through browser login.
5. Ingest HARs into API artifacts.
6. Generate fuzz plans.
7. Run read-only A/B comparison for object-scoped GET endpoints.
8. Summarize confirmed findings separately from candidates and blocked checks.
9. Do not claim a finding unless status/body evidence supports it.
```

## Finding Criteria

Confirmed finding:

- in-scope target
- authorized test accounts or permitted unauthenticated target
- reproducible request and response evidence
- secrets redacted
- clear expected secure result and vulnerable result
- no destructive action
- impact explained without accessing real third-party data

Candidate only:

- scanner output without response evidence
- one-account-only IDOR guess
- redacted value makes identity uncertain
- endpoint returns only public/shared data
- blocked by `403`, `404`, login redirect, or expected empty response

No finding:

- all cross-actor object requests denied
- user has legitimate membership to the object
- only self-data is returned
- evidence depends on brute force, mass enumeration, or out-of-scope behavior
