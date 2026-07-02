# 블랙박스 버그바운티 자동화 파이프라인 (DONZO)

## 0. 전체 목표

```text
목표:
허가된 bug bounty scope 안에서 블랙박스 기반으로 자산, 엔드포인트, API, 파라미터, 취약점 후보를 최대한 수집하고,
자동 exploit이 아니라 사람이 검증 가능한 취약점 후보 queue를 생성한다.

최종 산출물:
- assets.jsonl
- services.jsonl
- endpoints.jsonl
- params.jsonl
- candidates.jsonl
- findings.jsonl
- ranked.jsonl
- report.md
- evidence/
```

---

# 1. 최종 전체 파이프라인

```text
scope.yaml
   ↓
[0] Scope / Policy Validator
   ↓
[1] Asset Discovery
   ├─ subfinder
   ├─ amass
   ├─ bbot
   ├─ uncover
   ├─ chaos-client optional
   └─ cloud_enum optional
   ↓
[2] Asset Expansion
   ├─ alterx
   ├─ dnsx
   ├─ tlsx
   └─ wildcard filtering
   ↓
[3] Live Service Enrichment
   ├─ httpx
   ├─ naabu
   └─ technology fingerprint
   ↓
[4] URL / Endpoint Expansion
   ├─ katana
   ├─ gau
   ├─ waybackurls
   ├─ waymore
   └─ ParamSpider
   ↓
[5] Content / API Discovery
   ├─ ffuf
   ├─ feroxbuster
   ├─ kiterunner
   ├─ Swagger/OpenAPI finder
   └─ GraphQL finder
   ↓
[6] JavaScript Analysis
   ├─ JS collector
   ├─ endpoint extractor
   ├─ source map detector
   ├─ gitleaks
   └─ trufflehog
   ↓
[7] Parameter Mining
   ├─ URL parameter extraction
   ├─ Arjun
   ├─ gf pattern
   ├─ qsreplace
   └─ kxss reflection candidate
   ↓
[8] Vulnerability Candidate Engine
   ├─ BOLA / IDOR candidate
   ├─ SSRF parameter candidate
   ├─ open redirect candidate
   ├─ file disclosure candidate
   ├─ exposed admin/API candidate
   ├─ subdomain takeover candidate
   ├─ GraphQL candidate
   └─ secret exposure candidate
   ↓
[9] Controlled Scanner
   ├─ nuclei safe/deep policy
   ├─ ZAP baseline optional
   ├─ Dalfox candidate optional
   └─ interactsh optional
   ↓
[10] Normalize
   ↓
[11] Dedupe / Cluster
   ↓
[12] Risk Ranking
   ↓
[13] Evidence Builder
   ↓
[14] Manual Verification Queue
   ↓
[15] Report Generator
```

---

# 2. 실행 모드 설계

## Fast 모드

짧게 기본 리콘만 하는 모드.

```yaml
profile: fast

modules:
  - scope_validator
  - subfinder
  - dnsx
  - httpx
  - katana
  - nuclei_safe
  - normalize
  - dedupe
  - rank
  - report

use_case:
  - 빠른 대상 파악
  - 세미나 시연
  - 최초 MVP
```

---

## Normal 모드

일반적인 버그바운티 리콘 모드.

```yaml
profile: normal

modules:
  - scope_validator
  - subfinder
  - amass_passive
  - dnsx
  - httpx
  - naabu
  - katana
  - gau
  - waybackurls
  - nuclei_safe
  - swagger_finder
  - graphql_finder
  - parameter_extractor
  - basic_candidate_engine
  - normalize
  - dedupe
  - rank
  - report

use_case:
  - 일반 버그바운티 리콘
  - 하루 단위 분석
  - 실제 후보 수집
```

---

## Deep 모드

시간 오래 걸려도 취약점 후보를 더 많이 찾는 모드.

```yaml
profile: deep

modules:
  - scope_validator
  - subfinder
  - amass
  - bbot
  - uncover
  - cloud_enum
  - alterx
  - dnsx
  - tlsx
  - httpx
  - naabu
  - katana_headless
  - gau
  - waybackurls
  - waymore
  - ParamSpider
  - ffuf_safe
  - feroxbuster_safe
  - kiterunner
  - js_analyzer
  - sourcemap_detector
  - gitleaks
  - trufflehog
  - swagger_openapi_analyzer
  - graphql_analyzer
  - arjun
  - gf
  - qsreplace
  - kxss
  - nuclei_deep_safe
  - zap_baseline_optional
  - dalfox_candidate_optional
  - interactsh_optional
  - bola_idor_candidate_engine
  - normalize
  - dedupe
  - rank
  - evidence_builder
  - report

use_case:
  - 오래 걸려도 취약점 후보 최대 수집
  - 실제 버그바운티용
  - 연구/개발용 메인 목표
```

---

# 3. 단계별 세부 파이프라인

## [0] Scope / Policy Validator

가장 먼저 실행됨.
모든 단계는 이 결과를 기준으로 동작해야 함.

### 입력

```yaml
config/scope.yaml
config/rate_limit.yaml
config/nuclei_policy.yaml
```

### 역할

```text
- in-scope domain 확인
- out-of-scope domain 제거
- 금지된 test type 제거
- destructive / DoS / brute force / credential stuffing 차단
- rate limit 로드
- scan profile 결정
```

### 예시 설정

```yaml
program_name: "example-bounty"
profile: "deep"
mode: "authorized-only"

in_scope:
  domains:
    - "example.com"
    - "*.example.com"

out_of_scope:
  domains:
    - "payments.example.com"
    - "admin-prod.example.com"
  paths:
    - "/logout"
    - "/delete"
    - "/checkout"
    - "/payment"

blocked_tests:
  - dos
  - bruteforce
  - credential_stuffing
  - destructive_test
  - social_engineering
  - automatic_exploit
  - automatic_submission

scan_policy:
  passive_recon: true
  crawling: true
  port_scan: true
  content_discovery: true
  nuclei_scan: true
  zap_baseline: false
  oast: false
  active_exploit: false
```

### 출력

```text
output/state/policy.json
output/state/scope_resolved.json
```

---

## [1] Asset Discovery

서브도메인, 외부 노출 자산, 클라우드 자산 후보를 수집함.

### 사용하는 도구

```text
subfinder
amass
bbot
uncover
cloud_enum optional
chaos-client optional
```

### 흐름

```text
root domains
   ↓
subfinder
   ↓
amass passive
   ↓
bbot recursive
   ↓
uncover search engine assets
   ↓
cloud_enum public cloud resource candidate
   ↓
merge
   ↓
scope filter
```

### 출력

```text
output/raw/subfinder.txt
output/raw/amass.txt
output/raw/bbot.jsonl
output/raw/uncover.jsonl
output/raw/cloud_enum.txt
output/normalized/assets_raw.jsonl
```

### Asset 출력 예시

```json
{
  "asset": "staging-api.example.com",
  "type": "subdomain",
  "source": ["subfinder", "amass"],
  "in_scope": true,
  "risk_hints": ["staging_keyword", "api_keyword"]
}
```

---

## [2] Asset Expansion

기존 자산에서 더 많은 후보를 생성함.

### 사용하는 도구

```text
alterx
dnsx
tlsx
```

### 흐름

```text
assets_raw.jsonl
   ↓
alterx permutation
   ↓
dnsx resolve
   ↓
wildcard DNS filtering
   ↓
tlsx certificate / SAN enrichment
   ↓
validated assets
```

### 찾는 것

```text
- dev.example.com
- staging.example.com
- api-dev.example.com
- admin-old.example.com
- internal-like exposed host
- 인증서 SAN에 남아있는 도메인
```

### 출력

```text
output/raw/alterx_candidates.txt
output/raw/resolved.txt
output/raw/tlsx.jsonl
output/normalized/assets_validated.jsonl
```

---

## [3] Live Service Enrichment

살아있는 웹 서비스와 열린 포트를 확인함.

### 사용하는 도구

```text
httpx
naabu
```

### 흐름

```text
assets_validated.jsonl
   ↓
httpx
   ↓
live web services
   ↓
naabu
   ↓
open ports
   ↓
service enrichment
```

### httpx에서 수집할 값

```text
- URL
- status code
- title
- redirect chain
- content length
- web server
- tech stack
- favicon hash
- response time
```

### naabu에서 수집할 값

```text
- host
- port
- protocol
- discovered service
```

### 출력

```text
output/raw/httpx.jsonl
output/raw/naabu.txt
output/normalized/services.jsonl
output/derived/live_urls.txt
```

### Service 예시

```json
{
  "host": "api.example.com",
  "url": "https://api.example.com",
  "status_code": 200,
  "title": "API Server",
  "tech": ["nginx", "Spring Boot"],
  "ports": [80, 443, 8080],
  "risk_hints": ["api_service"]
}
```

---

## [4] URL / Endpoint Expansion

살아있는 웹과 과거 아카이브에서 URL을 최대한 수집함.

### 사용하는 도구

```text
katana
gau
waybackurls
waymore
ParamSpider
```

### 흐름

```text
live_urls.txt
   ↓
katana crawling
   ↓
archive URL collection
      ├─ gau
      ├─ waybackurls
      ├─ waymore
      └─ ParamSpider
   ↓
URL normalize
   ↓
dedupe
   ↓
httpx alive check
   ↓
endpoints.jsonl
```

### 수집 대상

```text
- 현재 페이지 링크
- JS에서 참조되는 API
- 과거 Wayback URL
- Common Crawl URL
- URLScan / OTX 등 공개 소스 URL
- query parameter 포함 URL
```

### 출력

```text
output/raw/katana.jsonl
output/raw/gau.txt
output/raw/waybackurls.txt
output/raw/waymore.txt
output/raw/paramspider.txt
output/normalized/endpoints_raw.jsonl
output/normalized/endpoints_alive.jsonl
```

---

## [5] Content / API Discovery

크롤링과 아카이브로 안 나온 숨은 경로와 API route를 찾음.

### 사용하는 도구

```text
ffuf
feroxbuster
kiterunner
custom swagger finder
custom graphql finder
```

### 흐름

```text
live services
   ↓
safe content discovery
   ├─ ffuf
   ├─ feroxbuster
   └─ kiterunner
   ↓
API document discovery
   ├─ /swagger.json
   ├─ /openapi.json
   ├─ /v3/api-docs
   ├─ /swagger-ui/
   ├─ /api-docs
   └─ /docs
   ↓
GraphQL endpoint discovery
   ├─ /graphql
   ├─ /graphiql
   └─ /playground
```

### 제한 조건

```yaml
content_discovery_policy:
  enabled_profile:
    - normal
    - deep
  max_rate: 2
  max_depth: 2
  exclude_paths:
    - /logout
    - /delete
    - /checkout
    - /payment
  destructive_methods_blocked: true
```

### 출력

```text
output/raw/ffuf.json
output/raw/feroxbuster.json
output/raw/kiterunner.json
output/normalized/discovered_paths.jsonl
output/normalized/api_docs.jsonl
output/normalized/graphql_candidates.jsonl
```

---

## [6] JavaScript Analysis

프론트엔드 JS에서 API, secret 후보, source map, hidden route를 찾음.

### 사용하는 도구

```text
katana
custom JS downloader
custom regex extractor
gitleaks
trufflehog
```

### 흐름

```text
endpoints_alive.jsonl
   ↓
JS file collect
   ↓
JS download
   ↓
endpoint extraction
   ↓
sourcemap detection
   ↓
secret candidate scan
   ↓
cloud config detection
```

### 찾는 것

```text
- /api/*
- /v1/*
- /v2/*
- /admin/*
- /internal/*
- /graphql
- source map 파일
- Firebase config
- Sentry DSN
- API key 후보
- cloud bucket 이름
- feature flag
- hidden route
```

### 출력

```text
output/raw/js_files.txt
output/raw/js_downloads/
output/raw/gitleaks.json
output/raw/trufflehog.json
output/normalized/js_endpoints.jsonl
output/normalized/secret_candidates.jsonl
output/normalized/sourcemap_candidates.jsonl
```

### Secret 후보 정책

```text
자동 사용 금지.
자동 검증 금지.
후보로만 저장.
수동 검증 전 scope와 프로그램 정책 확인.
```

---

## [7] Parameter Mining

취약점 후보를 만들기 위해 파라미터를 최대한 수집하고 분류함.

### 사용하는 도구

```text
Arjun
gf
qsreplace
kxss
custom parameter extractor
```

### 흐름

```text
endpoints_alive.jsonl
   ↓
query parameter extraction
   ↓
archive parameter extraction
   ↓
Arjun hidden parameter discovery
   ↓
parameter normalization
   ↓
parameter classification
   ↓
params.jsonl
```

### 파라미터 분류 기준

```yaml
parameter_classification:
  idor_candidates:
    - id
    - user_id
    - account_id
    - order_id
    - invoice_id
    - file_id
    - document_id
    - team_id
    - org_id

  redirect_candidates:
    - next
    - url
    - redirect
    - returnUrl
    - callback
    - continue

  ssrf_candidates:
    - url
    - uri
    - endpoint
    - host
    - domain
    - callback
    - webhook

  file_candidates:
    - file
    - path
    - filename
    - download
    - template
    - image

  xss_candidates:
    - q
    - s
    - search
    - keyword
    - query
    - name
    - message
```

### 출력

```text
output/raw/arjun.json
output/normalized/params.jsonl
output/normalized/parameter_candidates.jsonl
```

---

## [8] Vulnerability Candidate Engine

여기가 제일 중요함.
단순 스캐너 결과가 아니라, **취약점이 나올 가능성이 높은 후보**를 직접 생성함.

---

## 8-1. BOLA / IDOR Candidate Engine

### 입력

```text
endpoints_alive.jsonl
params.jsonl
api_docs.jsonl
js_endpoints.jsonl
```

### 탐지 기준

```text
- URL path에 object id 존재
- query parameter에 id류 값 존재
- user/order/invoice/document/team/org/account 키워드 존재
- JSON API 응답
- 인증 필요 endpoint로 추정
- read/write method 존재
```

### 후보 예시

```json
{
  "candidate_type": "BOLA_IDOR",
  "endpoint": "GET /api/v1/orders/{order_id}",
  "object_key": "order_id",
  "method": "GET",
  "risk_reason": [
    "object_id_in_path",
    "user_owned_resource_keyword",
    "returns_json"
  ],
  "verification": "manual_two_account_test_required",
  "auto_exploit": false
}
```

---

## 8-2. SSRF Candidate Engine

### 기준

```text
- url, uri, endpoint, webhook, callback, host 파라미터
- 외부 URL을 받는 API
- preview, fetch, import, callback 기능명
- webhook 설정 페이지
```

### 정책

```text
기본은 후보 생성만.
interactsh/OAST 테스트는 기본 OFF.
프로그램 정책 확인 후 수동 승인 필요.
```

---

## 8-3. Open Redirect Candidate Engine

### 기준

```text
- next
- redirect
- returnUrl
- callback
- continue
- url
```

### 출력

```json
{
  "candidate_type": "OPEN_REDIRECT",
  "url": "https://app.example.com/login?next=/dashboard",
  "parameter": "next",
  "verification": "manual_required",
  "auto_exploit": false
}
```

---

## 8-4. File Disclosure Candidate Engine

### 기준

```text
- file
- path
- filename
- download
- template
- image
- backup extension
- .bak
- .old
- .zip
- .tar.gz
- .log
- .env
- .config
```

---

## 8-5. Subdomain Takeover Candidate Engine

### 기준

```text
- CNAME 존재
- dangling DNS 가능성
- known provider fingerprint
- HTTP error fingerprint
```

### 정책

```text
자동 claim 금지.
후보로만 생성.
수동 검증 필요.
```

---

## 8-6. Secret Exposure Candidate Engine

### 입력

```text
secret_candidates.jsonl
js_endpoints.jsonl
services.jsonl
```

### 기준

```text
- secret 후보가 실제 in-scope asset과 연결되는지
- JS 파일 출처가 in-scope인지
- key/token 형태가 명확한지
- 공개 config인지 민감 secret인지 분류
```

### 정책

```text
자동 사용 금지.
자동 API 호출 금지.
수동 검증 필요.
```

---

## [9] Controlled Scanner

취약점 후보 스캔 단계.
모든 스캔은 정책 기반으로 제한함.

### 사용하는 도구

```text
nuclei
ZAP baseline optional
Dalfox optional
interactsh optional
```

---

## 9-1. nuclei

### Safe 기본 정책

```yaml
nuclei_policy:
  safe_default:
    include_tags:
      - exposure
      - misconfig
      - cve
      - takeover
      - panel
      - token
      - swagger
      - api
      - graphql
      - cloud
    exclude_tags:
      - dos
      - intrusive
      - destructive
      - bruteforce
      - fuzz
    severity:
      include:
        - low
        - medium
        - high
        - critical
      exclude:
        - info
```

### Deep 정책

```yaml
nuclei_policy:
  deep:
    include_tags:
      - exposure
      - misconfig
      - cve
      - takeover
      - panel
      - token
      - swagger
      - api
      - graphql
      - cloud
      - ssrf
      - xss
      - lfi
      - sqli
    require_policy_check_for:
      - ssrf
      - xss
      - sqli
      - lfi
```

### 출력

```text
output/raw/nuclei.jsonl
output/normalized/scanner_findings.jsonl
```

---

## 9-2. ZAP Baseline

### 실행 조건

```text
- profile이 normal 또는 deep
- zap_baseline이 true
- 로그인 필요 없는 웹앱
- 중요한 서비스로 랭킹된 대상
```

### 찾는 것

```text
- passive DAST 결과
- security header
- cookie flag
- 기본 misconfig
```

### 출력

```text
output/raw/zap/
output/normalized/zap_findings.jsonl
```

---

## 9-3. Dalfox Candidate

### 실행 조건

```text
- reflection candidate가 존재할 때
- profile deep
- policy에서 허용할 때
```

### 정책

```text
전체 URL에 무지성 실행 금지.
반사 후보에만 제한.
```

---

## 9-4. interactsh / OAST

### 실행 조건

```text
- oast enabled true
- 사용자가 명시적으로 허용
- 프로그램 정책상 OAST 테스트 허용
- SSRF/Blind 후보가 존재
```

### 정책

```text
기본 OFF.
자동 대량 테스트 금지.
저속 후보 검증만 허용.
```

---

# 4. Normalize 단계

각 도구의 출력 형식이 다르기 때문에 공통 schema로 통일함.

```text
subfinder       → txt
amass           → txt/json
bbot            → jsonl
httpx           → jsonl
katana          → jsonl
nuclei          → jsonl
ffuf            → json
feroxbuster     → json
zap             → json/html
gitleaks        → json
trufflehog      → json
```

## 공통 스키마

```text
Asset
Service
Endpoint
Parameter
Candidate
Finding
Evidence
```

---

## Asset Schema

```json
{
  "asset_id": "sha256(asset)",
  "program": "example-bounty",
  "asset": "api.example.com",
  "type": "subdomain",
  "sources": ["subfinder", "amass"],
  "in_scope": true,
  "first_seen": "2026-07-02T00:00:00Z",
  "last_seen": "2026-07-02T00:00:00Z",
  "risk_hints": ["api_keyword"]
}
```

---

## Endpoint Schema

```json
{
  "endpoint_id": "sha256(method_url)",
  "url": "https://api.example.com/api/v1/users?id=1",
  "method": "GET",
  "source": ["katana", "gau"],
  "status_code": 200,
  "content_type": "application/json",
  "params": ["id"],
  "requires_auth_guess": false,
  "risk_hints": ["api_endpoint", "id_parameter"]
}
```

---

## Candidate Schema

```json
{
  "candidate_id": "sha256(candidate_type_target)",
  "candidate_type": "BOLA_IDOR",
  "target": "https://api.example.com/api/v1/orders/123",
  "method": "GET",
  "source": ["parameter_mining", "api_discovery"],
  "risk_reason": [
    "object_id_in_path",
    "user_owned_resource_keyword",
    "returns_json"
  ],
  "confidence": 0.72,
  "verification_status": "manual_required",
  "auto_exploit": false
}
```

---

## Finding Schema

```json
{
  "finding_id": "sha256(template_target_evidence)",
  "title": "Public Swagger UI",
  "severity": "medium",
  "confidence": 0.84,
  "target": "https://api.example.com/swagger-ui/",
  "tool": "nuclei",
  "candidate_type": "EXPOSED_API_DOCS",
  "evidence": {
    "request_path": "output/evidence/finding-001/request.txt",
    "response_path": "output/evidence/finding-001/response.txt",
    "screenshot_path": "output/evidence/finding-001/screenshot.png"
  },
  "risk_score": 78,
  "verification_status": "needs_manual_review"
}
```

---

# 5. Dedupe / Cluster 단계

중복 결과를 묶음.

## 중복 기준

```text
- 같은 host
- 같은 path
- 같은 parameter
- 같은 nuclei template id
- 같은 candidate_type
- 유사한 title
- 유사한 response hash
```

## 예시

```text
/api/docs
/swagger-ui/
/swagger-ui/index.html
/v3/api-docs
```

이런 건 전부 `EXPOSED_API_DOCS` 그룹으로 묶을 수 있음.

## 출력

```text
output/normalized/candidates_deduped.jsonl
output/normalized/findings_deduped.jsonl
output/normalized/clusters.jsonl
```

---

# 6. Risk Ranking 단계

이 도구의 핵심 차별점임.
단순히 nuclei severity만 믿으면 안 됨.

## 최종 점수

```text
risk_score =
severity_score
+ confidence_score
+ bounty_likelihood_score
+ evidence_quality_score
+ correlation_score
- noise_penalty
- duplicate_penalty
- out_of_scope_penalty
```

---

## 점수 기준

```yaml
risk_ranking:
  severity_score:
    critical: 40
    high: 30
    medium: 20
    low: 10
    info: 0

  confidence_score:
    exact_match: 25
    strong_indicator: 15
    weak_indicator: 5

  bounty_likelihood_score:
    bola_idor_candidate: 35
    sensitive_data_exposure: 35
    leaked_secret_candidate: 30
    subdomain_takeover_candidate: 30
    unauthenticated_admin_api: 30
    public_swagger_with_sensitive_paths: 25
    graphql_introspection: 25
    ssrf_candidate: 20
    exposed_backup_file: 20
    reflected_xss_candidate: 15
    open_redirect_candidate: 8
    missing_security_header: 2

  evidence_quality_score:
    has_request_response: 10
    has_screenshot: 5
    reproducible_http_status: 5
    multiple_sources_confirmed: 10

  penalties:
    out_of_scope: -100
    noisy_template: -20
    duplicate: -30
    info_only: -15
    destructive_test_required: -100
```

---

## 우선순위 기준

```text
P0:
- leaked secret + in-scope asset correlation
- BOLA/IDOR write candidate
- 인증 없는 민감 API
- high-confidence subdomain takeover
- 공개 cloud storage 민감정보 후보

P1:
- 공개 Swagger/OpenAPI + 민감 endpoint
- GraphQL introspection/playground
- exposed backup/config/log
- high/critical CVE 후보
- SSRF/OAST 후보

P2:
- reflected XSS 후보
- open redirect 후보
- exposed admin panel
- medium CVE 후보
- file parameter 후보

P3:
- security header 누락
- cookie flag 단순 누락
- version disclosure
- banner disclosure
```

---

# 7. Evidence Builder

버그바운티에서 중요한 건 결국 증거임.

## 저장할 evidence

```text
- raw request
- raw response
- response hash
- screenshot
- redirect chain
- status code
- content length
- matched pattern
- source tool
- first_seen
- last_seen
- reproduction note
- manual verification checklist
```

## 디렉터리 구조

```text
output/
├── raw/
├── normalized/
├── derived/
├── evidence/
│   ├── finding-0001/
│   │   ├── request.txt
│   │   ├── response.txt
│   │   ├── screenshot.png
│   │   └── notes.md
│   ├── finding-0002/
│   │   ├── request.txt
│   │   ├── response.txt
│   │   └── notes.md
├── assets.jsonl
├── services.jsonl
├── endpoints.jsonl
├── params.jsonl
├── candidates.jsonl
├── findings.jsonl
├── ranked.jsonl
└── report.md
```

---

# 8. Manual Verification Queue

자동으로 “취약점 확정”하지 않음.
사람이 검증할 수 있는 queue를 생성함.

## Queue 예시

```json
{
  "priority": "P0",
  "candidate_type": "BOLA_IDOR",
  "target": "https://api.example.com/api/v1/orders/123",
  "reason": [
    "object_id_in_path",
    "order_keyword",
    "json_api",
    "authenticated_endpoint_guess"
  ],
  "manual_verification": [
    "두 개의 테스트 계정 준비",
    "계정 A에서 object id 확인",
    "계정 B 세션에서 동일 object 접근 가능 여부 확인",
    "응답의 소유자 정보와 민감 데이터 확인",
    "scope와 프로그램 정책 재확인"
  ],
  "auto_exploit": false
}
```

---

# 9. 최종 Report Generator

## 출력 파일

```text
output/report.md
output/ranked.jsonl
output/llm_prompt.md optional
```

## report.md 구조

```markdown
# Bug Bounty Recon Report

## 1. Target

- Program: example-bounty
- Profile: deep
- Mode: authorized-only

## 2. Summary

- Total assets:
- Live web services:
- Open ports:
- Endpoints:
- Parameters:
- Candidates:
- Scanner findings:
- P0:
- P1:
- P2:
- P3:

## 3. Priority Findings

### P0-001. BOLA / IDOR Candidate

- Target:
- Method:
- Parameter/Object:
- Confidence:
- Evidence:
- Reason:
- Manual Verification:
- Risk:
- Notes:

## 4. Asset Summary

## 5. API / GraphQL Summary

## 6. Secret Candidate Summary

## 7. Nuclei / ZAP Findings

## 8. Manual Verification Checklist

## 9. Out-of-Scope Removed Items

## 10. Appendix
```

---

# 10. 최종 CLI 설계

```bash
# 전체 실행
bbauto run -c config/scope.yaml -p deep -o output/

# 빠른 실행
bbauto run -c config/scope.yaml -p fast -o output/

# 일반 실행
bbauto run -c config/scope.yaml -p normal -o output/

# deep recon만 실행
bbauto recon -c config/scope.yaml -p deep -o output/

# JS 분석만 재실행
bbauto analyze js -i output/endpoints.jsonl -o output/

# API 분석만 재실행
bbauto analyze api -i output/endpoints.jsonl -o output/

# 파라미터 마이닝만 실행
bbauto mine params -i output/endpoints.jsonl -o output/

# 후보 생성만 실행
bbauto candidates build -i output/normalized/ -o output/

# 랭킹만 재계산
bbauto rank -i output/candidates.jsonl -o output/ranked.jsonl

# 리포트 생성
bbauto report -i output/ranked.jsonl -o output/report.md
```

---

# 11. DAG 구현용 작업 순서

개발할 때는 이 순서로 만들면 됨.

```text
v0.1 MVP:
1. scope.yaml parser
2. tool runner
3. subfinder module
4. dnsx module
5. httpx module
6. katana module
7. nuclei module
8. normalize module
9. dedupe module
10. simple ranker
11. report.md generator

v0.2 Normal:
1. amass passive
2. naabu
3. gau
4. waybackurls
5. swagger finder
6. graphql finder
7. parameter extractor
8. candidate schema
9. evidence directory

v0.3 Deep:
1. bbot
2. uncover
3. alterx
4. tlsx
5. waymore
6. ParamSpider
7. ffuf safe
8. feroxbuster safe
9. kiterunner
10. JS analyzer
11. sourcemap detector
12. gitleaks
13. trufflehog
14. Arjun
15. gf / qsreplace / kxss
16. BOLA / IDOR candidate engine
17. subdomain takeover candidate engine
18. secret correlation engine
19. advanced ranking
20. LLM report prompt
```

---

# 12. 최종 구현 구조

```text
bbauto/
├── README.md
├── pyproject.toml
├── config/
│   ├── scope.yaml
│   ├── rate_limit.yaml
│   ├── nuclei_policy.yaml
│   └── tools.yaml
├── bbauto/
│   ├── main.py
│   ├── core/
│   │   ├── config.py
│   │   ├── scope.py
│   │   ├── policy.py
│   │   ├── runner.py
│   │   ├── pipeline.py
│   │   ├── storage.py
│   │   ├── logger.py
│   │   └── state.py
│   ├── modules/
│   │   ├── subfinder.py
│   │   ├── amass.py
│   │   ├── bbot.py
│   │   ├── uncover.py
│   │   ├── alterx.py
│   │   ├── dnsx.py
│   │   ├── tlsx.py
│   │   ├── httpx.py
│   │   ├── naabu.py
│   │   ├── katana.py
│   │   ├── gau.py
│   │   ├── waybackurls.py
│   │   ├── waymore.py
│   │   ├── paramspider.py
│   │   ├── ffuf.py
│   │   ├── feroxbuster.py
│   │   ├── kiterunner.py
│   │   ├── nuclei.py
│   │   ├── zap.py
│   │   ├── dalfox.py
│   │   └── interactsh.py
│   ├── analyzers/
│   │   ├── js_analyzer.py
│   │   ├── sourcemap.py
│   │   ├── secret_analyzer.py
│   │   ├── api_analyzer.py
│   │   ├── graphql_analyzer.py
│   │   └── param_analyzer.py
│   ├── candidates/
│   │   ├── bola_idor.py
│   │   ├── ssrf.py
│   │   ├── open_redirect.py
│   │   ├── file_disclosure.py
│   │   ├── takeover.py
│   │   ├── secret_exposure.py
│   │   └── exposed_api_docs.py
│   ├── normalize/
│   │   ├── assets.py
│   │   ├── services.py
│   │   ├── endpoints.py
│   │   ├── params.py
│   │   ├── candidates.py
│   │   └── findings.py
│   ├── ranking/
│   │   ├── score.py
│   │   ├── rules.py
│   │   └── priority.py
│   ├── evidence/
│   │   ├── builder.py
│   │   ├── screenshot.py
│   │   └── request_response.py
│   ├── report/
│   │   ├── markdown.py
│   │   ├── json_export.py
│   │   ├── sarif.py
│   │   └── llm_prompt.py
│   └── schemas/
│       ├── asset.py
│       ├── service.py
│       ├── endpoint.py
│       ├── parameter.py
│       ├── candidate.py
│       └── finding.py
└── tests/
    ├── test_scope.py
    ├── test_policy.py
    ├── test_normalize.py
    ├── test_dedupe.py
    ├── test_ranking.py
    └── test_candidates.py
```

---

# 13. LLM Adjudication Layer

SCOUT식 구조를 웹 블랙박스 버그바운티에 맞게 적용한다.

```text
도구 / scanner / analyzer
   ↓
deterministic evidence
   ↓
rule-based candidate engine
   ↓
LLM Tribunal
   ├─ Evidence Summarizer
   ├─ Advocate
   ├─ Critic
   └─ Judge
   ↓
final risk ranking
   ↓
manual verification queue
```

Codex는 스캔을 수행하는 주체가 아니라, `output/evidence/`,
`ranked.jsonl`, request/response, endpoint metadata를 읽고 false positive,
impact, 수동 검증 우선순위를 보조 판단하는 레이어다.

## Verdict

```text
confirmed_candidate
likely_true_positive
needs_manual_review
likely_false_positive
out_of_scope_or_not_allowed
```

어떤 verdict도 자동 exploit이나 자동 제보를 의미하지 않는다.

## Backends

```text
1. Codex CLI primary
2. OpenAI API optional fallback
3. Claude API optional fallback
4. Ollama/local model optional research backend
```

Codex CLI는 파이프라인에서 직접 호출하지 않는다. 반드시 `CodexJudgeDriver`
같은 내부 gateway로 감싼다.

```text
EvidencePack
   ↓
redaction
   ↓
Codex job workspace
   ↓
codex exec --json --sandbox read-only --output-schema
   ↓
local JSON Schema validation
   ↓
retry / cache / SQLite job log / audit JSONL
   ↓
standard FindingVerdict
```

기본 설정은 다음 원칙을 따른다.

```yaml
llm:
  required: true
  primary_provider: codex_cli
  fail_closed: true
  failure_policy:
    fallback_to_rules: false
```

## Current LLM Call Sites

현재 구현된 실제 LLM 호출 지점은 다음 3개다.

```text
1. candidate_generator
   - 입력: endpoint/API/JS/parameter cluster JSON 또는 JSONL
   - 호출 단위: 개별 URL이 아니라 batch/cluster
   - 출력: manual-review candidate list

2. finding_triage
   - 입력: finding 1개
   - 호출 단위: finding 1개
   - 출력: FindingVerdict

3. report_writer
   - 입력: triaged/reviewable findings batch
   - 호출 단위: report draft 1개
   - 출력: Markdown draft JSON wrapper
```

rule-based logic은 판단자가 아니라 Evidence Pack 생성, redaction, scope/safety
filtering에만 사용한다. 외부 LLM verdict가 없으면 finding은 `llm_failed` 또는
`llm_pending` 상태로 남고 final ranking/report에 포함하지 않는다.

호출 횟수는 아래 원칙을 따른다.

```text
candidate_generator: batch 1개당 보통 1회, schema 실패 시 최대 max_attempts
finding_triage: finding 1개당 보통 1회, schema 실패 시 최대 max_attempts
report_writer: report draft 1개당 보통 1회, schema 실패 시 최대 max_attempts
cache hit / out-of-scope / --allow-external-llm 없음: 0회
```

---

# 14. 최종 요약

최종 파이프라인은 이렇게 잡으면 됨.

```text
1. scope.yaml로 허가 범위 고정
2. subfinder/amass/bbot/uncover로 자산 수집
3. alterx/dnsx/tlsx로 자산 확장과 검증
4. httpx/naabu로 살아있는 서비스 확인
5. katana/gau/waybackurls/waymore로 URL 수집
6. ffuf/feroxbuster/kiterunner로 숨은 경로와 API route 탐색
7. JS analyzer/gitleaks/trufflehog로 JS endpoint와 secret 후보 수집
8. Arjun/gf/qsreplace/kxss로 파라미터 마이닝
9. BOLA/IDOR/SSRF/open redirect/file disclosure/takeover 후보 생성
10. nuclei/ZAP/Dalfox/interactsh를 정책 기반으로 제한 실행
11. 모든 결과를 공통 schema로 normalize
12. 중복 제거와 cluster 생성
13. LLM Tribunal로 false positive와 impact를 보조 판정
14. final risk score로 P0~P3 랭킹
15. request/response/screenshot evidence 저장
16. 사람이 검증할 manual verification queue와 report.md 생성
```

진짜 취약점 발견률을 올리는 핵심은 **nuclei 많이 돌리기**가 아니라,
**JS/API/파라미터/BOLA·IDOR 후보 생성/랭킹 엔진**을 얼마나 잘 만드느냐임.
