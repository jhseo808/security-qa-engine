from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path

from engine.qa_converter import QATestCase
from reports.markdown import generate


def _tc(
    id: str,
    title: str,
    priority: str = "P1",
    severity: str = "critical",
) -> QATestCase:
    return QATestCase(
        id=id,
        priority=priority,
        action_status="fix_now",
        qa_verifiable="qa_verifiable",
        verification_status="unverified",
        evidence_quality="strong",
        title=title,
        severity=severity,
        category="injection",
        location="https://example.com/api",
        reproduction_steps="1. Send payload\n2. Observe error",
        fix_suggestion="Use parameterized queries",
        evidence="payload: ' OR 1=1--",
        source_finding_id="f-001",
    )


def _finding(
    title: str,
    severity: str = "critical",
    false_positive: bool = False,
) -> dict:
    return {
        "id": "f-001",
        "title": title,
        "severity": severity,
        "category": "injection",
        "location": "https://example.com",
        "priority": 1,
        "priority_reason": "base severity=critical",
        "false_positive": false_positive,
        "action_status": "fix_now",
        "qa_verifiable": "qa_verifiable",
        "verification_status": "unverified",
        "evidence_quality": "strong",
        "reproduction_steps": "",
        "fix_suggestion": "",
    }


_METADATA = {
    "target": "https://example.com",
    "scanned_at": "2026-03-26T10:00:00Z",
    "scan_type": "url",
    "coverage_status": "partial",
    "report_confidence": "medium",
    "failed_scanners": ["zap"],
    "ai_status": "fallback",
    "ai_notes": "AI failed; fallback prioritization used.",
}


@contextmanager
def _output_dir() -> Path:
    root = Path(r"C:\Users\")
    root.mkdir(exist_ok=True)
    path = root / f"case-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_files_created() -> None:
    with _output_dir() as output_dir:
        generate([_tc("TC-001", "SQL Injection")], [_finding("SQL Injection")], _METADATA, output_dir)
        assert (output_dir / "test_cases.md").exists()
        assert (output_dir / "report_dev.md").exists()


def test_test_cases_contains_tc_header() -> None:
    with _output_dir() as output_dir:
        generate([_tc("TC-001", "SQL Injection")], [_finding("SQL Injection")], _METADATA, output_dir)
        content = (output_dir / "test_cases.md").read_text(encoding="utf-8")
        assert "## TC-001: SQL Injection" in content


def test_test_cases_contains_checklist() -> None:
    with _output_dir() as output_dir:
        generate([_tc("TC-001", "SQL Injection")], [_finding("SQL Injection")], _METADATA, output_dir)
        content = (output_dir / "test_cases.md").read_text(encoding="utf-8")
        assert "- [ ] Verify the fix is applied" in content
        assert "- [ ] Confirm the issue is no longer reproducible" in content
        assert "Action Status" in content
        assert "QA Verifiable" in content
        assert "Verification Status" in content
        assert "Evidence Quality" in content


def test_report_dev_contains_summary_and_warning() -> None:
    with _output_dir() as output_dir:
        generate([_tc("TC-001", "SQL Injection")], [_finding("SQL Injection")], _METADATA, output_dir)
        content = (output_dir / "report_dev.md").read_text(encoding="utf-8")
        assert "https://example.com" in content
        assert "Critical" in content
        assert "Partial Coverage" in content
        assert "AI failed; fallback prioritization used." in content
        assert "Fix Now" in content


def test_report_dev_priority_table() -> None:
    with _output_dir() as output_dir:
        generate([_tc("TC-001", "SQL Injection")], [_finding("SQL Injection")], _METADATA, output_dir)
        content = (output_dir / "report_dev.md").read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "base severity=critical" in content


def test_empty_findings_no_error() -> None:
    with _output_dir() as output_dir:
        generate([], [], _METADATA, output_dir)
        content = (output_dir / "test_cases.md").read_text(encoding="utf-8")
        assert "No actionable QA test cases were generated." in content


def test_scan_date_in_output() -> None:
    with _output_dir() as output_dir:
        generate([], [], _METADATA, output_dir)
        content = (output_dir / "test_cases.md").read_text(encoding="utf-8")
        assert "2026-03-26" in content
