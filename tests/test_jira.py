from __future__ import annotations

from types import SimpleNamespace

from engine.qa_converter import QATestCase
from integrations.jira import JiraClient, _build_payload, _dedup_label


def _test_case() -> QATestCase:
    return QATestCase(
        id="TC-001",
        priority="P1",
        action_status="fix_now",
        qa_verifiable="qa_verifiable",
        verification_status="unverified",
        evidence_quality="strong",
        title="SQL Injection",
        severity="critical",
        category="injection",
        location="https://example.com/login",
        reproduction_steps="1. submit payload",
        fix_suggestion="use parameterized queries",
        evidence="payload observed",
        source_finding_id="f-001",
    )


class _Response:
    def __init__(self, payload: dict | None = None) -> None:
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _Session:
    def __init__(self, search_payload: dict | None = None) -> None:
        self.search_payload = search_payload or {"issues": []}
        self.get_calls: list[dict] = []
        self.post_calls: list[dict] = []
        self.put_calls: list[dict] = []

    def get(self, url: str, params: dict, timeout: int) -> _Response:
        self.get_calls.append({"url": url, "params": params, "timeout": timeout})
        return _Response(self.search_payload)

    def post(self, url: str, json: dict, timeout: int) -> _Response:
        self.post_calls.append({"url": url, "json": json, "timeout": timeout})
        return _Response({"key": "SEC-123"})

    def put(self, url: str, json: dict, timeout: int) -> _Response:
        self.put_calls.append({"url": url, "json": json, "timeout": timeout})
        return _Response({})


def _client(session: _Session) -> JiraClient:
    client = JiraClient(SimpleNamespace(
        jira_url="https://example.atlassian.net",
        jira_user="user@example.com",
        jira_token="token",
        jira_project_key="SEC",
    ))
    client._session = session
    return client


def test_build_payload_includes_action_status_and_dedup_label() -> None:
    test_case = _test_case()

    payload = _build_payload(test_case, "SEC")
    text_nodes = payload["fields"]["description"]["content"]
    text_values = [node["content"][0]["text"] for node in text_nodes]

    assert any("Action Status:" in value for value in text_values)
    assert any("fix_now" in value for value in text_values)
    assert any("QA Verifiable:" in value for value in text_values)
    assert any("Verification Status:" in value for value in text_values)
    assert any("Evidence Quality:" in value for value in text_values)
    assert _dedup_label(test_case) in payload["fields"]["labels"]
    assert any("Dedup Key:" in value for value in text_values)


def test_find_existing_issue_key_uses_dedup_label() -> None:
    session = _Session(search_payload={"issues": [{"key": "SEC-9"}]})
    client = _client(session)

    key = client.find_existing_issue_key(_test_case())

    assert key == "SEC-9"
    assert "labels =" in session.get_calls[0]["params"]["jql"]
    assert _dedup_label(_test_case()) in session.get_calls[0]["params"]["jql"]


def test_create_or_update_issue_updates_existing_issue() -> None:
    session = _Session(search_payload={"issues": [{"key": "SEC-9"}]})
    client = _client(session)

    key = client.create_or_update_issue(_test_case())

    assert key == "SEC-9"
    assert len(session.put_calls) == 1
    assert len(session.post_calls) == 0


def test_create_or_update_issue_creates_when_missing() -> None:
    session = _Session(search_payload={"issues": []})
    client = _client(session)

    key = client.create_or_update_issue(_test_case())

    assert key == "SEC-123"
    assert len(session.post_calls) == 1
    assert len(session.put_calls) == 0
