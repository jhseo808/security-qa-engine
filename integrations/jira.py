from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import requests

from config import Config
from engine.qa_converter import QATestCase
from utils.logger import get_logger

if TYPE_CHECKING:
    from scanner.normalizer import FilteredFinding

logger = get_logger(__name__)

_PRIORITY_MAP = {"P1": "Highest", "P2": "High", "P3": "Medium"}


class JiraClient:
    def __init__(self, config: Config) -> None:
        self._base = config.jira_url.rstrip("/") + "/rest/api/3"  # type: ignore[operator]
        self._project_key = config.jira_project_key
        self._session = requests.Session()
        self._session.auth = (config.jira_user, config.jira_token)  # type: ignore[arg-type]
        self._session.headers["Accept"] = "application/json"
        self._session.headers["Content-Type"] = "application/json"

    def create_issue(self, test_case: QATestCase) -> str:
        payload = _build_payload(test_case, self._project_key)
        response = self._session.post(f"{self._base}/issue", json=payload, timeout=30)
        response.raise_for_status()
        return response.json()["key"]

    def create_or_update_issue(self, test_case: QATestCase) -> str:
        existing_key = self.find_existing_issue_key(test_case)
        payload = _build_payload(test_case, self._project_key)

        if existing_key:
            response = self._session.put(
                f"{self._base}/issue/{existing_key}",
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            logger.info(f"Updated Jira issue: {existing_key} - {test_case['title']}")
            return existing_key

        response = self._session.post(f"{self._base}/issue", json=payload, timeout=30)
        response.raise_for_status()
        key = response.json()["key"]
        logger.info(f"Created Jira issue: {key} - {test_case['title']}")
        return key

    def create_issues(self, test_cases: list[QATestCase]) -> list[str]:
        keys: list[str] = []
        for test_case in test_cases:
            try:
                keys.append(self.create_or_update_issue(test_case))
            except Exception as error:
                logger.warning(f"Failed to create or update Jira issue [{test_case['id']}]: {error}")
        return keys

    def post_delta_comments(self, findings: list[FilteredFinding]) -> None:
        """delta_status가 있는 finding의 Jira 티켓에 코멘트를 추가한다."""
        for finding in findings:
            delta_status = finding.get("delta_status")
            if delta_status not in ("fixed", "persisted"):
                continue
            if finding.get("false_positive"):
                continue

            issue_key = self._find_issue_by_finding(finding)
            if not issue_key:
                logger.debug(f"Jira 이슈 없음, 건너뜀: {finding.get('title')}")
                continue

            try:
                if delta_status == "fixed":
                    self._add_comment(
                        issue_key,
                        "✅ *Verified* — 최신 스캔에서 해당 취약점이 감지되지 않았습니다. 수정을 확인하고 티켓을 닫아주세요.",
                    )
                    logger.info(f"Verified comment added: {issue_key} - {finding.get('title')}")
                elif delta_status == "persisted":
                    self._add_comment(
                        issue_key,
                        "🔁 *Still Present* — 최신 스캔에서 동일한 취약점이 다시 감지되었습니다. 수정이 완료되지 않았습니다.",
                    )
                    logger.info(f"Still Present comment added: {issue_key} - {finding.get('title')}")
            except Exception as error:
                logger.warning(f"Delta 코멘트 실패 [{issue_key}]: {error}")

    def _find_issue_by_finding(self, finding: FilteredFinding) -> str | None:
        dedup_label = _dedup_label_from_finding(finding)
        jql = (
            f'project = "{self._project_key}" '
            f'AND labels = "{dedup_label}" '
            'ORDER BY updated DESC'
        )
        response = self._session.post(
            f"{self._base}/search/jql",
            json={"jql": jql, "maxResults": 1, "fields": ["key"]},
            timeout=30,
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])
        return issues[0].get("key") if issues else None

    def _add_comment(self, issue_key: str, text: str) -> None:
        body = {
            "body": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": text}],
                    }
                ],
            }
        }
        response = self._session.post(
            f"{self._base}/issue/{issue_key}/comment",
            json=body,
            timeout=30,
        )
        response.raise_for_status()

    def find_existing_issue_key(self, test_case: QATestCase) -> str | None:
        dedup_label = _dedup_label(test_case)
        jql = (
            f'project = "{self._project_key}" '
            f'AND labels = "{dedup_label}" '
            'ORDER BY updated DESC'
        )
        response = self._session.post(
            f"{self._base}/search/jql",
            json={
                "jql": jql,
                "maxResults": 1,
                "fields": ["key"],
            },
            timeout=30,
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])
        if not issues:
            return None
        return issues[0].get("key")


def _build_payload(test_case: QATestCase, project_key: str) -> dict:
    dedup_label = _dedup_label(test_case)
    parts = [
        f"Action Status:\n{test_case.get('action_status', 'unknown')}",
        f"QA Verifiable:\n{test_case.get('qa_verifiable', 'unknown')}",
        f"Verification Status:\n{test_case.get('verification_status', 'unknown')}",
        f"Evidence Quality:\n{test_case.get('evidence_quality', 'unknown')}",
        f"Dedup Key:\n{dedup_label}",
        f"Reproduction:\n{test_case['reproduction_steps']}" if test_case["reproduction_steps"] else "",
        f"Fix Suggestion:\n{test_case['fix_suggestion']}" if test_case["fix_suggestion"] else "",
        f"Evidence:\n{test_case['evidence']}" if test_case["evidence"] else "",
        f"Location: {test_case['location']}",
        f"Category: {test_case['category']}",
        f"Source Finding ID: {test_case['source_finding_id']}",
    ]
    body_text = "\n\n".join(part for part in parts if part)

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[Security] {test_case['title']}",
            "description": _to_adf(body_text),
            "issuetype": {"id": "10008"},
            "priority": {"name": _PRIORITY_MAP.get(test_case["priority"], "Medium")},
            "labels": ["security", "qa-auto", dedup_label],
        }
    }


def _dedup_label(test_case: QATestCase) -> str:
    fingerprint = "|".join(
        [
            str(test_case.get("title", "")).strip().lower(),
            str(test_case.get("category", "")).strip().lower(),
            str(test_case.get("location", "")).strip().lower(),
        ]
    )
    digest = hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:12]
    return f"sqe-{digest}"


def _dedup_label_from_finding(finding: FilteredFinding) -> str:
    fingerprint = "|".join(
        [
            str(finding.get("title", "")).strip().lower(),
            str(finding.get("category", "")).strip().lower(),
            str(finding.get("location", "")).strip().lower(),
        ]
    )
    digest = hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:12]
    return f"sqe-{digest}"


def _to_adf(text: str) -> dict:
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in text.splitlines()
        if line.strip()
    ]
    if not paragraphs:
        paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": ""}]}]
    return {"version": 1, "type": "doc", "content": paragraphs}
