from __future__ import annotations

from typing import TypedDict


class QATestCase(TypedDict):
    id: str                 # TC-001, TC-002, ...
    priority: str           # P1, P2, P3
    action_status: str
    qa_verifiable: str
    verification_status: str
    evidence_quality: str
    title: str
    severity: str
    category: str
    location: str
    reproduction_steps: str
    fix_suggestion: str
    evidence: str
    source_finding_id: str


def convert(findings: list[dict]) -> list[QATestCase]:
    """false_positive 제외 후 FindingList → QATestCase 리스트 변환."""
    result: list[QATestCase] = []
    counter = 1
    for f in findings:
        if f.get("false_positive"):
            continue
        result.append(QATestCase(
            id=f"TC-{counter:03d}",
            priority=_rank_to_priority(f.get("priority", 5)),
            action_status=f.get("action_status", _default_action_status(f)),
            qa_verifiable=f.get("qa_verifiable", _default_qa_verifiable(f)),
            verification_status=f.get("verification_status", _default_verification_status(f)),
            evidence_quality=f.get("evidence_quality", _default_evidence_quality(f)),
            title=f.get("title", ""),
            severity=f.get("severity", "info"),
            category=f.get("category", "other"),
            location=f.get("location", ""),
            reproduction_steps=f.get("reproduction_steps", ""),
            fix_suggestion=f.get("fix_suggestion", ""),
            evidence=f.get("evidence", ""),
            source_finding_id=f.get("id", ""),
        ))
        counter += 1
    return result


def _rank_to_priority(rank: int) -> str:
    if rank <= 2:
        return "P1"
    if rank == 3:
        return "P2"
    return "P3"


def _default_action_status(finding: dict) -> str:
    severity = finding.get("severity", "info")
    if severity in {"critical", "high"}:
        return "fix_now"
    if severity == "medium":
        return "review_needed"
    return "backlog"


def _default_qa_verifiable(finding: dict) -> str:
    source = finding.get("source", "")
    category = finding.get("category", "")

    if source in {"headers", "zap", "nuclei", "ssl_labs", "secrets"}:
        return "qa_verifiable"
    if source == "shodan" or category == "cve":
        return "requires_security_review"
    if source in {"semgrep", "dependency"} or category in {"dependency", "semgrep"}:
        return "requires_dev_check"
    return "qa_verifiable"


def _default_verification_status(finding: dict) -> str:
    if _default_qa_verifiable(finding) == "qa_verifiable":
        return "unverified"
    return "needs_manual_check"


def _default_evidence_quality(finding: dict) -> str:
    source = finding.get("source", "")
    evidence = str(finding.get("evidence", "")).strip()
    raw = finding.get("raw", {}) or {}

    if source == "shodan":
        return "manual_check_required"
    if source in {"headers", "ssl_labs", "secrets"}:
        return "strong" if evidence else "medium"
    if source in {"zap", "nuclei"}:
        return "strong" if evidence else "medium"
    if source == "semgrep":
        return "medium" if evidence else "weak"
    if source == "dependency":
        if raw.get("fix_versions") or raw.get("fix_available") or raw.get("cvss_score") or raw.get("cvss"):
            return "medium"
        return "weak"
    return "medium" if evidence else "weak"
