from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    zap_api_key: str = field(default_factory=lambda: os.getenv("ZAP_API_KEY", "changeme"))
    zap_port: int = field(default_factory=lambda: int(os.getenv("ZAP_PORT", "8080")))
    anthropic_api_key: str | None = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY") or None)
    shodan_api_key: str | None = field(default_factory=lambda: os.getenv("SHODAN_API_KEY") or None)
    jira_url: str | None = field(default_factory=lambda: os.getenv("JIRA_URL") or None)
    jira_user: str | None = field(default_factory=lambda: os.getenv("JIRA_USER") or None)
    jira_token: str | None = field(default_factory=lambda: os.getenv("JIRA_TOKEN") or None)
    jira_project_key: str = field(default_factory=lambda: os.getenv("JIRA_PROJECT_KEY", "SEC"))
    jira_type: str = field(default_factory=lambda: os.getenv("JIRA_TYPE", "cloud"))
    slack_webhook: str | None = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK") or None)


def load_config() -> Config:
    return Config()


def preflight_check(config: Config, mode: str, include_zap: bool = True) -> None:
    from utils.logger import get_logger

    logger = get_logger(__name__)
    readiness = _build_readiness_report(config, mode, include_zap=include_zap)

    logger.info("Preflight readiness:")
    for line in readiness["lines"]:
        logger.info(f"  {line}")

    if readiness["fatal_errors"]:
        for error in readiness["fatal_errors"]:
            logger.error(error)
        sys.exit(1)


def _build_readiness_report(
    config: Config,
    mode: str,
    include_zap: bool = True,
) -> dict[str, list[str]]:
    lines: list[str] = []
    fatal_errors: list[str] = []

    if mode == "url":
        docker_running = _is_docker_running()
        lines.append(f"Docker running: {_yes_no(docker_running)}")
        if include_zap and not docker_running:
            fatal_errors.append("Docker is required for the full URL scan path that includes ZAP/nuclei.")

        lines.append(f"nmap available: {_yes_no(docker_running)} (via Docker)")
        lines.append(f"nuclei available: {_yes_no(docker_running)} (via Docker)")
        lines.append(f"Shodan API configured: {_yes_no(bool(config.shodan_api_key))}")
        lines.append(f"Anthropic API configured: {_yes_no(bool(config.anthropic_api_key))}")
        lines.append(f"Jira configured: {_yes_no(_jira_ready(config))}")
        return {"lines": lines, "fatal_errors": fatal_errors}

    if mode == "local":
        semgrep_available = _command_exists("semgrep")
        pip_audit_available = _command_exists("pip-audit")
        detect_secrets_available = _command_exists("detect-secrets")
        npm_available = _command_exists("npm")

        lines.append(f"semgrep available: {_yes_no(semgrep_available)}")
        lines.append(f"pip-audit available: {_yes_no(pip_audit_available)}")
        lines.append(f"detect-secrets available: {_yes_no(detect_secrets_available)}")
        lines.append(f"npm available: {_yes_no(npm_available)}")
        lines.append(f"Anthropic API configured: {_yes_no(bool(config.anthropic_api_key))}")
        lines.append(f"Jira configured: {_yes_no(_jira_ready(config))}")
        return {"lines": lines, "fatal_errors": fatal_errors}

    if mode == "war":
        docker_running = _is_docker_running()
        lines.append(f"Docker running: {_yes_no(docker_running)}")
        if not docker_running:
            fatal_errors.append("Docker is required for WAR/SCA scan (grype runs via Docker).")
        lines.append(f"grype available: {_yes_no(docker_running)} (via Docker)")
        lines.append(f"Anthropic API configured: {_yes_no(bool(config.anthropic_api_key))}")
        lines.append(f"Jira configured: {_yes_no(_jira_ready(config))}")
        return {"lines": lines, "fatal_errors": fatal_errors}

    lines.append(f"Unknown preflight mode: {mode}")
    return {"lines": lines, "fatal_errors": fatal_errors}


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _jira_ready(config: Config) -> bool:
    return bool(config.jira_url and config.jira_user and config.jira_token)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _is_docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
