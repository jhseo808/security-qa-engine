# Todo

---

## 🚧 PR/CI 통합 + 다중 프로젝트 배포 (예정)

이 도구를 조직 안에 자연스럽게 녹이고, 다른 프로젝트에서도 쉽게 재사용할 수 있도록 패키징 및 CI 통합.

### 목표 흐름

```
PR 오픈        → --path 코드 스캔  → PR comment + artifact
staging 배포   → --url URL 스캔   → Jira + Slack + artifact
release 배포   → --url --baseline → Jira delta 코멘트 + Slack
```

```
다른 프로젝트 적용:
  uses: org/security-qa-engine@v1
  with:
    mode: url
    target: https://staging.myapp.com
    jira-project: MY-PROJECT
```

### Tasks

#### 1. Docker Image 빌드
- [ ] `Dockerfile` 작성 — scan.py 실행 환경 패키징
- [ ] `.dockerignore` 정리
- [ ] 이미지 빌드 + 실행 검증
  ```bash
  docker build -t security-qa-engine .
  docker run --rm security-qa-engine --url https://target.com --skip-zap --skip-ai
  ```

#### 2. GitHub Actions workflow 작성
- [ ] `.github/workflows/security-pr.yml` — PR 트리거, `--path` 코드 스캔
- [ ] `.github/workflows/security-staging.yml` — staging 배포 트리거, `--url` 스캔
- [ ] `.github/workflows/security-release.yml` — release 트리거, `--url --baseline` regression 스캔
- [ ] 스캔 결과 artifact 저장 (`upload-artifact`)

#### 3. PR comment 연동
- [ ] `integrations/github.py` 신규 생성
- [ ] GitHub API로 PR에 스캔 결과 요약 코멘트 자동 등록
- [ ] 이미 코멘트가 있으면 update (중복 방지)

#### 4. Slack 연동
- [ ] `integrations/slack.py` 신규 생성
- [ ] 스캔 완료 시 결과 요약 Slack 메시지 전송
- [ ] fix_now 항목이 있을 때만 알림 (노이즈 최소화)
- [ ] `.env`에 `SLACK_WEBHOOK` 추가 (이미 .env.example에 있음)

#### 5. Reusable GitHub Action 래퍼
- [ ] `action.yml` 작성 — `uses: org/security-qa-engine@v1` 형태로 재사용 가능
- [ ] inputs: `mode` / `target` / `jira-project` / `baseline` / `slack-webhook`
- [ ] 다른 프로젝트에서 workflow 한 파일로 통합 가능하도록

#### 6. 테스트
- [ ] `tests/test_github.py` — PR comment 생성 / update 로직
- [ ] `tests/test_slack.py` — Slack 메시지 포맷
- [ ] 기존 테스트 전체 통과 확인

### 구현 순서

1 → 2 → 3 → 4 → 5 → 6

Docker가 기반이므로 먼저 만들고, Actions workflow → 연동 순으로 진행한다.

### 보류

- **Scanner Correlation** — finding 간 연관성 분석. CI 통합 후 실제 데이터가 쌓이면 진행.

---
---

## ✅ 완료 히스토리

### ✅ Delta + Regression Workflow

QA팀이 Jira 티켓 기반으로 보안 수정 사항을 regression 검증하는 워크플로우.

- [x] `engine/delta.py` — compare() 함수 (new / persisted / fixed 분류)
- [x] `scanner/normalizer.py` — FilteredFinding에 delta_status 필드 추가
- [x] `scan.py` — --baseline 옵션, delta 적용 로직
- [x] `reports/markdown.py` — Delta 요약 섹션 + finding 카드 배지
- [x] `integrations/jira.py` — Verified / Still Present 코멘트 자동 추가
- [x] `tests/test_delta.py` — 11개 테스트 (전체 96개 통과)

### ✅ WAR / SCA 점검 기능

WAR 파일 또는 WEB-INF 디렉터리 기반 Java 의존성 SCA 점검.

- [x] `scanner/local/sbom.py` — grype(CVE) + web.xml 보안 설정 점검
- [x] `scanner/normalizer.py` — grype / webxml finding 정규화, normalize_sbom() 추가
- [x] `scan.py` — --war 옵션, _run_war_scan() 구현
- [x] `config.py` — war 모드 preflight
- [x] `tests/test_sbom.py` — 19개 테스트 (전체 115개 통과)
