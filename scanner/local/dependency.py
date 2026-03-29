from __future__ import annotations

import json
import subprocess
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

_TIMEOUT = 120


def scan(path: str) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_run_pip_audit(path))
    findings.extend(_run_npm_audit(path))
    logger.info(f"Dependency scan complete: {len(findings)} findings")
    return findings


def _run_pip_audit(path: str) -> list[dict]:
    req_file = Path(path) / "requirements.txt"
    if not req_file.exists():
        logger.debug(f"Skipping pip-audit because requirements.txt is missing: {path}")
        return []

    logger.info("Running pip-audit...")
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "-r", str(req_file)],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except FileNotFoundError:
        logger.warning("pip-audit is not installed. Skipping Python dependency audit.")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("pip-audit timed out.")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[dict] = []
    for dependency in data.get("dependencies", []):
        for vulnerability in dependency.get("vulns", []):
            findings.append({
                "source": "pip-audit",
                "package": dependency.get("name", ""),
                "version": dependency.get("version", ""),
                "vuln_id": vulnerability.get("id", ""),
                "description": vulnerability.get("description", ""),
                "fix_versions": vulnerability.get("fix_versions", []),
                "aliases": vulnerability.get("aliases", []),
                "cvss_score": _extract_pip_cvss(vulnerability),
                "is_direct": dependency.get("dependencies") is None,
                "advisory": vulnerability,
            })
    return findings


def _run_npm_audit(path: str) -> list[dict]:
    pkg_file = Path(path) / "package.json"
    if not pkg_file.exists():
        logger.debug(f"Skipping npm audit because package.json is missing: {path}")
        return []

    logger.info("Running npm audit...")
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            cwd=path,
        )
    except FileNotFoundError:
        logger.warning("npm is not installed. Skipping npm audit.")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("npm audit timed out.")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[dict] = []
    for name, vulnerability in data.get("vulnerabilities", {}).items():
        findings.append({
            "source": "npm-audit",
            "package": name,
            "severity": vulnerability.get("severity", "unknown"),
            "description": vulnerability.get("title", ""),
            "via": [item if isinstance(item, str) else item.get("title", "") for item in vulnerability.get("via", [])],
            "fix_available": bool(vulnerability.get("fixAvailable")),
            "cvss_score": _extract_npm_cvss(vulnerability),
            "is_direct": vulnerability.get("isDirect"),
            "effects": vulnerability.get("effects", []),
            "range": vulnerability.get("range", ""),
            "nodes": vulnerability.get("nodes", []),
            "advisory": vulnerability,
        })
    return findings


def _extract_pip_cvss(vulnerability: dict) -> float | None:
    for alias in vulnerability.get("aliases", []):
        if isinstance(alias, dict):
            score = alias.get("cvss_score") or alias.get("cvss")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _extract_npm_cvss(vulnerability: dict) -> float | None:
    for key in ("cvss", "cvss_score"):
        score = vulnerability.get(key)
        if isinstance(score, (int, float)):
            return float(score)
    return None
