from __future__ import annotations

from types import SimpleNamespace

import config


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        shodan_api_key="shodan-key",
        anthropic_api_key="anthropic-key",
        jira_url="https://jira.example",
        jira_user="user",
        jira_token="token",
    )


def test_build_readiness_report_for_local_mode(monkeypatch) -> None:
    monkeypatch.setattr(config, "_command_exists", lambda command: command in {"semgrep", "npm"})
    report = config._build_readiness_report(_config(), "local")
    assert "semgrep available: yes" in report["lines"]
    assert "pip-audit available: no" in report["lines"]
    assert report["fatal_errors"] == []


def test_build_readiness_report_for_url_mode(monkeypatch) -> None:
    monkeypatch.setattr(config, "_is_docker_running", lambda: False)
    monkeypatch.setattr(config, "_command_exists", lambda command: command in {"nmap", "nuclei"})
    report = config._build_readiness_report(_config(), "url")
    assert "Docker running: no" in report["lines"]
    assert "nmap available: no (via Docker)" in report["lines"]
    assert "nuclei available: no (via Docker)" in report["lines"]
    assert len(report["fatal_errors"]) == 1


def test_build_readiness_report_for_url_mode_without_zap_requirement(monkeypatch) -> None:
    monkeypatch.setattr(config, "_is_docker_running", lambda: False)
    monkeypatch.setattr(config, "_command_exists", lambda command: command == "nmap")
    report = config._build_readiness_report(_config(), "url", include_zap=False)
    assert "Docker running: no" in report["lines"]
    assert "nmap available: no (via Docker)" in report["lines"]
    assert report["fatal_errors"] == []
