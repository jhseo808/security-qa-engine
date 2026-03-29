from __future__ import annotations

import json
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import scan


def _config(api_key: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(anthropic_api_key=api_key)


def _result() -> dict:
    return {
        "scan_id": "scan-1",
        "scan_type": "url",
        "target": "https://example.com",
        "scanned_at": "2026-03-27T00:00:00Z",
        "scanners_run": ["headers"],
        "scanners_failed": ["zap"],
        "expected_scanners": ["headers", "zap"],
        "executed_scanners": ["headers"],
        "failed_scanners": ["zap"],
        "coverage_status": "partial",
        "report_confidence": "medium",
        "findings": [
            {
                "id": "f-1",
                "source": "headers",
                "title": "Missing HSTS",
                "severity": "high",
                "cvss_score": None,
                "category": "headers",
                "location": "https://example.com",
                "description": "missing hsts",
                "evidence": "header absent",
                "raw": {},
            }
        ],
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


def test_build_filtered_findings_manual_required_without_api_key() -> None:
    findings, ai_status, ai_notes = scan._build_filtered_findings(_result(), _config(), skip_ai=False)
    assert ai_status == "manual_required"
    assert "ANTHROPIC_API_KEY" in ai_notes
    assert findings[0]["priority"] <= 5


def test_build_filtered_findings_skipped() -> None:
    findings, ai_status, ai_notes = scan._build_filtered_findings(_result(), _config("dummy"), skip_ai=True)
    assert ai_status == "skipped"
    assert "skipped" in ai_notes.lower()
    assert findings[0]["false_positive"] is False


def test_save_and_report_creates_filtered_and_reports() -> None:
    orchestrator_result = SimpleNamespace(
        findings=_result()["findings"],
        scanners_run=["headers"],
        scanners_failed=["zap"],
    )

    with _output_dir() as output_dir:
        scan._save_and_report(
            target="https://example.com",
            scan_type="url",
            result=orchestrator_result,
            output_dir=output_dir,
            skip_ai=True,
            config=_config("dummy"),
            expected_scanners=["headers", "zap"],
        )

        raw_data = json.loads((output_dir / "raw_results.json").read_text(encoding="utf-8"))
        filtered_data = json.loads((output_dir / "filtered_results.json").read_text(encoding="utf-8"))

        assert raw_data["coverage_status"] == "partial"
        assert filtered_data["ai_status"] == "skipped"
        assert (output_dir / "test_cases.md").exists()
        assert (output_dir / "report_dev.md").exists()


def test_run_from_filtered_supports_legacy_filtered_schema() -> None:
    legacy_filtered = {
        "scan_id": "auto",
        "scan_type": "url",
        "target": "http://legacy.test",
        "scanned_at": "2026-03-26T14:39:22.000000+00:00",
        "filtered_at": "2026-03-26T14:50:00.000000+00:00",
        "findings": [
            {
                "id": "f-legacy-1",
                "source": "zap",
                "title": "Legacy Finding",
                "severity": "high",
                "cvss_score": 7.5,
                "category": "csrf",
                "location": "http://legacy.test/login",
                "description": "legacy schema compatibility",
                "evidence": "proof",
                "raw": {},
                "priority": 1,
                "false_positive": False,
                "reproduction_steps": "1. reproduce",
                "fix_suggestion": "fix",
            }
        ],
    }

    with _output_dir() as input_dir, _output_dir() as output_dir:
        filtered_file = input_dir / "filtered_results.json"
        filtered_file.write_text(json.dumps(legacy_filtered, ensure_ascii=False), encoding="utf-8")

        args = SimpleNamespace(
            from_filtered=str(filtered_file),
            output=str(output_dir),
            skip_jira=True,
        )
        scan._run_from_filtered(args)

        generated_dirs = [path for path in output_dir.iterdir() if path.is_dir()]
        assert len(generated_dirs) == 1
        report_dir = generated_dirs[0]
        report_content = (report_dir / "report_dev.md").read_text(encoding="utf-8")
        assert "Legacy Finding" in report_content
        assert "Coverage**: Unknown" in report_content


def test_count_by_action_status_ignores_false_positives() -> None:
    findings = [
        {"action_status": "fix_now", "false_positive": False},
        {"action_status": "review_needed", "false_positive": False},
        {"action_status": "backlog", "false_positive": False},
        {"action_status": "fix_now", "false_positive": True},
    ]

    counts = scan._count_by_action_status(findings)

    assert counts == {
        "fix_now": 1,
        "review_needed": 1,
        "backlog": 1,
    }


def test_expected_url_scanners_include_network() -> None:
    config = SimpleNamespace(shodan_api_key="shodan-key")

    assert scan._expected_url_scanners(config, skip_zap=False) == [
        "headers",
        "db",
        "server",
        "network",
        "ssl_labs",
        "shodan",
        "nuclei",
        "zap",
    ]
