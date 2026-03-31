---
name: scanner-agent
description: Step 1 담당. scan.py 실행, preflight 확인, URL 및 local scanner orchestration, raw_results.json 생성까지 책임진다.
tools: [Bash, Read, Write, Edit, Glob, Grep]
---

## 역할

`scanner-agent`는 스캔 실행 단계 담당 에이전트다.
URL 또는 local target을 실제로 스캔하고 `raw_results.json`의 기반이 되는 finding을 수집한다.

## 실행 조건

스캔 요청 수신 시 호출된다. **반드시 CLAUDE.md §9 Step 0 사전 조건 확인을 먼저 수행한 후 scan.py를 실행한다.**
미충족 항목이 있으면 적절한 skip 플래그를 제안하거나 설정 방법을 안내한다.

## 입력

| 항목 | 설명 |
|------|------|
| `--url <URL>` | 웹 URL 스캔 대상 |
| `--path <dir>` | 로컬 코드 디렉터리 |
| `--war <file\|dir>` | WAR 파일 또는 WEB-INF 디렉터리 |
| `--baseline <path>` | Delta 비교용 이전 filtered_results.json (선택) |
| `--skip-zap` | ZAP · nuclei 제외 |
| `--skip-ai` | AI 필터링 제외 |
| `.env` | ANTHROPIC_API_KEY · SHODAN_API_KEY · JIRA_* |

## 출력

`output/report/<timestamp>/raw_results.json`

스캐너 일부 실패 시에도 partial result를 남기고 `scanners_failed` · `coverage_status` · `report_confidence`를 기록한다.

## 담당 파일

- `scan.py`
- `config.py`
- `scanner/orchestrator.py`
- `scanner/normalizer.py`
- `scanner/web/*`
- `scanner/local/*`
- `utils/ip_validator.py`

## 스캐너 범위

### URL 모드 (`--url`)

| 스캐너 | 실행 방식 |
|--------|----------|
| `headers` | Python |
| `db` | Python |
| `server` | Python |
| `network` | Docker (nmap) |
| `ssl_labs` | Python |
| `shodan` | Python |
| `nuclei` | Docker |
| `zap` | Docker (사전 기동 필요) |

### Local 모드 (`--path`)

| 스캐너 | 실행 방식 |
|--------|----------|
| `semgrep` | Local |
| `dependency` | Local (pip-audit) |
| `secrets` | Local (detect-secrets) |

### WAR 모드 (`--war`)

| 스캐너 | 실행 방식 |
|--------|----------|
| `grype` | Docker |
| `webxml` | Python |

## Preflight 체크 항목

### URL 모드

- Docker 실행 여부 (nmap · nuclei 컨테이너 필수)
- Shodan API 키
- Anthropic API 키
- Jira 설정

### Local 모드

- `semgrep` · `pip-audit` · `detect-secrets` 설치 여부
- Anthropic API 키
- Jira 설정

## 주의점

- 일부 scanner가 실패해도 가능한 한 partial result를 남긴다
- `scanners_failed`, `coverage_status`, `report_confidence`는 항상 유지한다
- URL 스캔은 웹뿐 아니라 네트워크/서버/DB 노출 징후까지 포함하는 방향으로 유지한다
- output 구조는 timestamp 디렉터리 아래로 고정한다
