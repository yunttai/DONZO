# Codex 기반 보안/버그바운티 자동화 프로젝트 구조 설계 요청

너는 OpenAI Codex CLI / Codex App / Codex GitHub Review / Codex Skills / Codex Subagents / Codex Hooks / Codex Harness를 최대한 활용해서 보안 자동화 프로젝트 구조를 설계해야 한다.

이 프로젝트는 블랙박스 버그바운티 자동화 프로젝트다.

## 핵심 목표

- 허가된 bug bounty scope 안에서만 동작하는 정찰/분석 자동화
- 서브도메인, 서비스, 웹 엔드포인트, 공개 메타데이터 수집
- 취약점 후보를 자동 정리하되, 최종 판단은 사람이 수행
- false positive를 줄이기 위한 finding validation harness 제공
- Codex가 작업할 때 항상 scope, safety, test, report 규칙을 따르게 구성
- Codex CLI, Codex App, Codex GitHub Review, codex exec, subagents, skills, hooks, rules, MCP, output schema를 적극 사용
- 실제 공격, 인증 우회, destructive test, DoS, brute force, credential stuffing, session hijacking, 데이터 유출 시도는 금지

## Codex에서 사용할 주요 기능

### 1. `AGENTS.md`
Codex가 프로젝트 작업 전에 읽는 기본 지침 파일이다.

여기에는 다음을 넣는다.

- 프로젝트 목적
- 허가된 작업 범위
- 금지 행위
- 실행 명령
- 테스트 명령
- 결과물 형식
- 코드 스타일
- 보안 정책
- PR 리뷰 기준
- done definition

### 2. `.codex/config.toml`
Codex 프로젝트 설정이다.

여기에는 다음을 넣는다.

- 기본 모델
- reasoning effort
- sandbox mode
- approval policy
- auto review
- subagent thread 제한
- MCP 서버 설정
- status line 설정

### 3. `.codex/agents/*.toml`
Codex subagent용 커스텀 에이전트다.

필수 에이전트:

- `scope_guard`: 허가 범위 검증 담당
- `recon_planner`: 정찰 계획 수립 담당
- `artifact_parser`: recon output 파싱 담당
- `finding_validator`: 취약점 후보 검증 담당
- `security_reviewer`: 보안 리뷰 담당
- `patch_worker`: 코드 수정 담당
- `report_writer`: 버그바운티 보고서 작성 담당
- `docs_researcher`: 공식 문서/API 확인 담당

### 4. `.agents/skills/*/SKILL.md`
Codex skill이다.

필수 스킬:

- `bugbounty-scope`
- `safe-recon-planner`
- `finding-validator`
- `report-writer`
- `codex-harness-runner`
- `security-code-review`
- `ci-failure-triage`

### 5. `.codex/hooks.json`
Codex lifecycle hook이다.

필수 훅:

- 사용자 프롬프트에서 토큰/쿠키/API Key 패턴 감지
- 위험한 Bash 명령 차단
- scope 파일 없이 recon 실행 차단
- 결과물에 secret 포함 여부 검사
- report 작성 전 필수 필드 검증
- 작업 종료 시 summary 생성

### 6. `.codex/rules/*.rules`
Codex command approval rule이다.

필수 규칙:

- destructive command forbidden
- network/recon command prompt
- git read allow
- git write prompt
- package install prompt
- secret 관련 명령 forbidden

### 7. `harness/`
Codex가 안정적으로 반복 실행할 수 있는 실행 하네스다.

harness는 Codex의 판단만 믿지 않고, deterministic script, schema, fixture, eval, CI, redaction, scope validation으로 결과를 통제하는 구조다.

필수 역할:

- 입력 검증
- scope 검증
- output schema 검증
- 결과 중복 제거
- secret redaction
- finding severity normalization
- report draft generation
- toy target 기반 안전 테스트
- CI에서 `codex exec` 검증
- Codex가 만든 결과를 사람이 검토하기 좋은 JSON/Markdown으로 저장

---

# 최종 폴더 구조

```text
project/
├── AGENTS.md
├── AGENTS.override.md
├── README.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── package.json
├── scope.example.yaml
├── .codex/
│   ├── config.toml
│   ├── hooks.json
│   ├── agents/
│   │   ├── scope_guard.toml
│   │   ├── recon_planner.toml
│   │   ├── artifact_parser.toml
│   │   ├── finding_validator.toml
│   │   ├── security_reviewer.toml
│   │   ├── patch_worker.toml
│   │   ├── report_writer.toml
│   │   └── docs_researcher.toml
│   ├── hooks/
│   │   ├── pre_tool_use_policy.py
│   │   ├── permission_request.py
│   │   ├── post_tool_use_review.py
│   │   ├── user_prompt_guard.py
│   │   └── stop_summary.py
│   └── rules/
│       ├── default.rules
│       ├── recon.rules
│       ├── git.rules
│       └── package-manager.rules
├── .agents/
│   └── skills/
│       ├── bugbounty-scope/
│       │   ├── SKILL.md
│       │   └── references/
│       │       └── scope-policy.md
│       ├── safe-recon-planner/
│       │   ├── SKILL.md
│       │   ├── references/
│       │   │   └── recon-boundaries.md
│       │   └── scripts/
│       │       └── summarize_scope.py
│       ├── finding-validator/
│       │   ├── SKILL.md
│       │   ├── references/
│       │   │   ├── validation-checklist.md
│       │   │   └── severity-mapping.md
│       │   └── scripts/
│       │       └── normalize_finding.py
│       ├── report-writer/
│       │   ├── SKILL.md
│       │   ├── assets/
│       │   │   └── bugbounty-report-template.md
│       │   └── references/
│       │       └── report-quality.md
│       ├── security-code-review/
│       │   ├── SKILL.md
│       │   └── references/
│       │       └── secure-review-checklist.md
│       └── codex-harness-runner/
│           ├── SKILL.md
│           ├── scripts/
│           │   └── run_harness.py
│           └── references/
│               └── harness-contract.md
├── harness/
│   ├── README.md
│   ├── scope.example.yaml
│   ├── policy/
│   │   ├── safety-policy.md
│   │   ├── allowed-actions.yaml
│   │   └── forbidden-actions.yaml
│   ├── schemas/
│   │   ├── scope.schema.json
│   │   ├── recon-result.schema.json
│   │   ├── finding.schema.json
│   │   ├── triage-result.schema.json
│   │   └── report.schema.json
│   ├── prompts/
│   │   ├── recon-plan.md
│   │   ├── finding-triage.md
│   │   ├── report-draft.md
│   │   └── pr-review.md
│   ├── scripts/
│   │   ├── codex_exec_recon_plan.sh
│   │   ├── codex_exec_finding_triage.sh
│   │   ├── codex_exec_report_draft.sh
│   │   ├── validate_scope.py
│   │   ├── validate_json_schema.py
│   │   ├── redact_secrets.py
│   │   ├── normalize_findings.py
│   │   ├── dedupe_findings.py
│   │   ├── generate_report.py
│   │   └── run_evals.py
│   ├── fixtures/
│   │   ├── toy-target/
│   │   │   ├── README.md
│   │   │   ├── docker-compose.yml
│   │   │   └── app/
│   │   └── sample-artifacts/
│   │       ├── subdomains.txt
│   │       ├── httpx.jsonl
│   │       ├── endpoints.json
│   │       └── findings.raw.json
│   ├── evals/
│   │   ├── cases/
│   │   │   ├── scope-guard.md
│   │   │   ├── false-positive-triage.md
│   │   │   ├── report-quality.md
│   │   │   └── secret-redaction.md
│   │   ├── expected/
│   │   │   ├── scope-guard.expected.json
│   │   │   ├── false-positive-triage.expected.json
│   │   │   ├── report-quality.expected.json
│   │   │   └── secret-redaction.expected.json
│   │   └── rubric.yaml
│   └── ci/
│       ├── codex-review.yml
│       ├── codex-harness-check.yml
│       └── codex-autofix-on-ci-failure.yml
├── src/
│   ├── recon/
│   ├── triage/
│   ├── reporting/
│   ├── safety/
│   └── utils/
├── findings/
│   ├── raw/
│   ├── normalized/
│   └── reviewed/
├── reports/
│   ├── drafts/
│   └── final/
└── artifacts/
    ├── codex/
    ├── recon/
    ├── evals/
    └── logs/