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
donzo doctor -c scope.example.yaml
donzo scope check -c scope.example.yaml --target https://api.example.com
donzo plan -c scope.example.yaml -p normal
donzo candidates generate -c scope.example.yaml -i harness/fixtures/sample-artifacts/endpoints.json --allow-external-llm
donzo tribunal run -c scope.example.yaml -i harness/fixtures/sample-artifacts/swagger-finding.json --driver codex_cli --allow-external-llm
donzo report draft -c scope.example.yaml -i harness/fixtures/sample-artifacts/findings.raw.json -o reports/drafts/report.md --allow-external-llm
```

Deterministic MVP flow without live recon:

```bash
donzo normalize -c scope.example.yaml --kind asset -i harness/fixtures/sample-artifacts/subdomains.txt -o artifacts/recon/assets.jsonl
donzo normalize -c scope.example.yaml --kind endpoint -i harness/fixtures/sample-artifacts/endpoints.json -o artifacts/recon/endpoints.jsonl
donzo analyze js -c scope.example.yaml -i harness/fixtures/sample-artifacts/app.js --base-url https://app.example.com -o artifacts/recon/js-endpoints.jsonl --candidates-output findings/normalized/js-candidates.jsonl
donzo analyze openapi -c scope.example.yaml -i harness/fixtures/sample-artifacts/openapi.json --base-url https://api.example.com -o artifacts/recon/openapi-endpoints.jsonl --candidates-output findings/normalized/openapi-candidates.jsonl
donzo analyze collection -c scope.example.yaml -i harness/fixtures/sample-artifacts/postman-collection.json -o artifacts/recon/collection-endpoints.jsonl
donzo ingest-har -c scope.example.yaml -i harness/fixtures/sample-artifacts/traffic.har --actor user_A --state logged_in -o artifacts/recon/traffic.jsonl --api-endpoints-output artifacts/recon/api-endpoints.jsonl --schema-diff-output artifacts/recon/schema-diff.jsonl
donzo candidates build -c scope.example.yaml -i artifacts/recon/endpoints.jsonl -o findings/normalized/candidates.jsonl
donzo rank -i findings/normalized/candidates.jsonl -o findings/reviewed/ranked.jsonl
donzo report render -c scope.example.yaml -i findings/reviewed/ranked.jsonl -o reports/drafts/report.md
donzo run-fixture -c scope.example.yaml --endpoints harness/fixtures/sample-artifacts/endpoints.json -o artifacts/recon/mvp-smoke
donzo run-fixture -c scope.example.yaml -p normal --endpoints harness/fixtures/sample-artifacts/endpoints.json --archive-urls harness/fixtures/sample-artifacts/archive-urls.txt -o artifacts/recon/normal-smoke
donzo run-fixture -c scope.example.yaml -p normal --endpoints harness/fixtures/sample-artifacts/endpoints.json --js-file harness/fixtures/sample-artifacts/app.js --js-base-url https://app.example.com --openapi harness/fixtures/sample-artifacts/openapi.json --openapi-base-url https://api.example.com -o artifacts/recon/normal-static-smoke
donzo run-fixture -c scope.example.yaml -p normal --endpoints harness/fixtures/sample-artifacts/endpoints.json --har harness/fixtures/sample-artifacts/traffic.har --traffic-actor user_A --traffic-state logged_in -o artifacts/recon/har-modeling-smoke
```

Fast, normal, and deep recon orchestration:

```bash
donzo tools check
donzo tools check --profile normal
donzo tools check --profile deep
donzo tools matrix
donzo doctor -c scope.example.yaml --profile normal
donzo doctor -c scope.example.yaml --profile deep
donzo run -c scope.example.yaml -p fast -o artifacts/recon/fast-plan
donzo run -c scope.example.yaml -p normal -o artifacts/recon/normal-plan
donzo run -c scope.example.yaml -p deep -o artifacts/recon/deep-plan
donzo run -c scope.example.yaml -p fast -o output/fast --execute
donzo run -c scope.example.yaml -p normal -o output/normal --execute
donzo run -c scope.example.yaml -p deep -o output/deep --execute
donzo run -c scope.example.yaml -p deep -o output/deep-llm --execute --llm-triage --allow-external-llm
donzo run -c scope.example.yaml -p deep -o output/deep-new --execute --compare-to output/deep
donzo auth template -c scope.example.yaml
donzo auth check -c scope.example.yaml --target https://app.example.com/lms
donzo diff --previous output/deep --current output/deep-new
donzo review summary -r output/deep --markdown
donzo review queue -r output/deep --include-filtered
donzo review debug -r output/deep -o output/deep/verification-debug.md
donzo review triage-queue -r output/deep
```

`donzo run` is dry-run by default and writes a scoped command plan. It only
executes network-facing tools when `--execute` is present, and execution still
requires scope/policy validation plus installed ProjectDiscovery binaries.
Supported recon tools receive profile scope rate controls in their command
plans: `subfinder`, `dnsx`, `httpx`, `katana`, and `gau` use
`rate_limit.max_requests_per_second`, `rate_limit.max_concurrency`, and
`rate_limit.timeout_seconds` where their CLIs support those flags.
During `--execute` runs, DONZO prints numbered progress bars to stderr while
keeping the final machine-readable JSON on stdout. Use `--no-progress` to
disable the terminal progress display.
Every `donzo run` starts with a profile-aware tool preflight and writes
`tool-preflight.json` plus `state.json`; execution fails closed before recon if
any planned required tool is missing. `donzo tools matrix` prints the fast and
normal/deep profile tool matrix, and the same policy is documented in
`harness/policy/tool-matrix.yaml`.
The normal profile extends fast with archive URL collection through `gau` and
`waybackurls`; those URLs are scope-filtered, normalized into endpoints, and
fed into parameter/API-docs/GraphQL candidate generation. Local static analyzers
also support JavaScript endpoint extraction and OpenAPI path/parameter parsing
without issuing requests. Normal local processing also derives scoped
OpenAPI/Swagger documentation URL candidates from known origins, GraphQL
endpoint artifacts, JavaScript sourcemap URL candidates, and optional naabu
port enrichment when `port_scan` is enabled and a `naabu.jsonl` artifact exists.
During live `--execute` runs, DONZO also performs bounded GET-only OpenAPI
schema enrichment: it checks common JSON/YAML schema paths per origin, parses
valid OpenAPI/Swagger documents, and adds the document's paths, methods, path
parameters, query parameters, and JSON/form body fields as scoped endpoints.
Report `api-docs` counts only include verified docs or schemas parsed during
that enrichment, not every guessed Swagger/ReDoc URL.
API discovery also adds a small fixed set of common application/API bases such
as `/lms`, `/portal`, `/dashboard`, `/api`, and `/graphql` to the scoped crawl
surface. These are bounded seed paths, not directory brute force.
Live normal/deep runs also fetch public `robots.txt` and sitemap URLs with the
same low-rate probe settings, then scope-filter declared paths into
`declared-endpoints.jsonl`. Local Postman and Insomnia JSON exports can be
parsed with `donzo analyze collection`; DONZO normalizes only in-scope requests
and treats resulting findings as manual-review candidates.
If `authenticated_crawl.enabled` is true, DONZO reads auth material only from
environment variables, passes redacted headers to supported safe crawling/probe
steps, and never writes the header value to JSON, Markdown, or dashboard
artifacts.
The CLI loads a project-local `.env` file automatically before command
execution. Existing shell environment values win over `.env` values. Set
`DONZO_DISABLE_DOTENV=1` to disable this behavior for a command. Do not commit
real cookies, tokens, or provider keys.
The deep profile runs the normal required toolchain and adds safe deep-mode
processing. Installed optional passive tools (`alterx`, `amass`, `bbot`,
`uncover`) run before `dnsx`; DONZO scope-filters their output into
`derived/candidate_assets.txt`, then feeds that file to `dnsx`, `httpx`, and
later service enrichment. Deep archive and parameter tooling (`waymore`,
`paramspider`, `qsreplace`, passive `arjun`) is connected through
`derived/archive_urls.txt` and `derived/live_urls.txt`. Local secret-pattern
tools (`gitleaks`, `trufflehog`) scan only derived in-scope artifacts and emit
redacted manual-review `SECRET_EXPOSURE` candidates when they find patterns.
Missing optional tools are recorded as skipped instead of blocking the run.
On WSL, `bbot` also needs system packages installed before it can run:

```bash
sudo apt update
sudo apt install -y unzip p7zip-full libssl-dev openssl
```

For an authorized high-coverage deep run, put provider keys/auth cookies and
`DONZO_USE_TOOL_DEFAULT_LIMITS=1` in `.env`, then run:

```bash
uv run donzo run -c scope.club.yaml -p deep -o artifacts/recon/mjsec-maxperf --execute
```

Common ProjectDiscovery `uncover` provider environment variables are
`SHODAN_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORGANIZATION_ID`, `FOFA_EMAIL`,
`FOFA_KEY`, `ZOOMEYE_API_KEY`, and `NETLAS_API_KEY`. Legacy
`CENSYS_API_ID`/`CENSYS_API_SECRET` are still accepted for compatibility, but
new Censys setup should use `CENSYS_API_TOKEN` and `CENSYS_ORGANIZATION_ID`.
DONZO automatically passes an explicit `uncover -e` engine list for the
providers configured in the environment, so unused/missing provider keys are not
selected.

Riskier deep tools remain policy-gated: `naabu` requires `port_scan: true`,
`nuclei` requires `nuclei_scan: true`, and `kiterunner`/`kxss` require
`content_discovery: true` plus allowed test types. The installed `gf` binary is
checked by `donzo tools check`; actual pattern execution requires user-managed
patterns under the gf home directory (`~/.gf` or `~/.config/gf`), so DONZO does
not modify that directory automatically.

When executed, the pipeline writes `assets.jsonl`, `services.jsonl`,
`endpoints.jsonl`, `params.jsonl`, `candidates.jsonl`, `findings.jsonl`,
`candidates-verified.jsonl`, `candidates-filtered.jsonl`, `ranked.jsonl`,
`clusters.jsonl`, `api-docs.jsonl`,
`graphql-endpoints.jsonl`, `source-maps.jsonl`, `port-services.jsonl`,
`verification-summary.json`, `verification-probes.jsonl`,
`soft404-baselines.jsonl`, `cluster-evidence-packs.jsonl`,
`technology-inference.jsonl`, `api-semantic-map.jsonl`, `llm-triage-input-packs.jsonl`,
`review-summary.json`, `review-queue.json`,
`llm-triage-queue.json`,
`llm-triage-summary.json` when `--llm-triage` is used,
`declared-endpoints.jsonl`, `dashboard.json`, `dashboard.html`,
`run-diff.json`/`run-diff.md` when `--compare-to` is used,
`verification-debug.md`, `review.md`, `normalized/*.jsonl`, `recon-result.json`,
`state.json`, `evidence/*/notes.md`, and `report.md`.
`candidates.jsonl`
remains the raw candidate stream; ranking and reporting use
`candidates-verified.jsonl`. Reports include verification, cluster, and manual
verification queue summaries before the full candidate list. Use `review.md` for
the shortest human inspection path and `verification-debug.md` to understand why
candidates were filtered. Open `dashboard.html` for a compact local run summary
with counts, filter categories, tool failures, LLM status, artifact links,
search, and sortable tables. LLM summaries include requested call count,
external job count, estimated cache hits, and usage metadata when Codex emits it.
`technology-inference.jsonl` records passive stack/API guesses from httpx,
tlsx, endpoint paths, and API artifacts; these are context signals, not
confirmed findings.
`api-semantic-map.jsonl` records inferred endpoint resource/action/auth
questions from path structure, OpenAPI metadata, JS callsites, and collection
metadata; these are prioritization signals for manual API review, not confirmed
bugs.
`traffic.jsonl`, `request-schemas.jsonl`, and `response-schemas.jsonl` can be
generated from redacted HAR input. DONZO merges those observations into
`api-endpoints.jsonl`, classifies path/query/body/response fields in
`parameter-classification.jsonl`, and writes `schema-diff.jsonl` for read-only,
mass-assignment, and excessive-data candidates.
The API modeling layer also writes `api-dependency-graph.json`,
`api-sequences.jsonl`, `state-transitions.jsonl`, `handler-hypotheses.jsonl`,
`security-invariants.jsonl`, `manual-test-plans.jsonl`, and
`oracle-templates.jsonl`. These artifacts are planning aids for authorized
manual review only; they do not perform automatic exploitation or mutate
targets.
`llm-triage-input-packs.jsonl` includes normal reviewable cluster packs plus
supplemental filtered-candidate recheck packs so the LLM can spot possible
false-negative filtering without turning filtered candidates into reportable
findings automatically.

The LLM layer is an adjudication aid. It currently has four explicit call
sites: `candidate_generator`, `finding_triage`, `cluster_triage`, and
`report_writer`. Normal
execution is one Codex call per submitted batch or finding, with up to
`llm.drivers.codex_cli.max_attempts` retries for invalid schema output. The
default external LLM driver is `codex_cli`, using `gpt-5.6` with
`model_reasoning_effort=xhigh`, wrapped by a job workspace, JSON
Schema validator, retry loop, cache, SQLite job log, and audit JSONL. Actual
`donzo run` execution enables cluster triage and external Codex CLI calls by
default when `llm.required: true`; use `--no-llm-triage` or `--no-external-llm`
only when intentionally disabling that behavior. `--llm-limit 0` submits all
LLM triage input packs, including supplemental filtered raw-candidate rechecks.

Cluster triage can be run automatically at the end of `donzo run`:

```powershell
uv run donzo run -c scope.example.yaml -p deep -o artifacts/recon/deep-llm --execute
```

Or manually against one generated evidence pack:

```powershell
donzo clusters triage -c scope.example.yaml -i artifacts/recon/normal-smoke/cluster-evidence-packs/<pack>.json --allow-external-llm
```

If the external LLM call fails, DONZO marks the item
`llm_failed` and excludes it from final ranking/reporting. It does not exploit
targets, validate secrets, or submit reports.
