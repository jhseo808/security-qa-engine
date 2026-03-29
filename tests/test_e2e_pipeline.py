from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from engine import prioritizer, qa_converter
from reports import markdown
from scanner import normalizer


def test_fixture_driven_e2e_pipeline() -> None:
    fixture = json.loads(
        Path("tests/fixtures/raw_scan_result.json").read_text(encoding="utf-8")
    )

    findings = fixture["findings"]
    filtered = normalizer.to_filtered_findings(findings)

    filtered[0]["reproduction_steps"] = "1. Request the homepage\n2. Verify CSP is absent"
    filtered[0]["fix_suggestion"] = "Set a strict Content-Security-Policy header."
    filtered[1]["reproduction_steps"] = "1. Inspect requirements.txt\n2. Confirm vulnerable version"
    filtered[1]["fix_suggestion"] = "Upgrade requests to 2.32.4 or later."
    filtered[2]["false_positive"] = True

    prioritized = prioritizer.prioritize(filtered)
    test_cases = qa_converter.convert(prioritized)

    output_root = Path(r"C:\Users\HP\.codex\memories\test_artifacts")
    output_root.mkdir(exist_ok=True)
    output_dir = output_root / f"e2e-{uuid.uuid4().hex}"
    output_dir.mkdir()

    try:
        metadata = {
            "target": fixture["target"],
            "scanned_at": fixture["scanned_at"],
            "scan_type": fixture["scan_type"],
            "coverage_status": fixture["coverage_status"],
            "report_confidence": fixture["report_confidence"],
            "failed_scanners": fixture["failed_scanners"],
            "ai_status": "skipped",
            "ai_notes": "Fixture-driven fallback path.",
        }
        markdown.generate(test_cases, prioritized, metadata, output_dir)

        report = (output_dir / "report_dev.md").read_text(encoding="utf-8")
        qa_report = (output_dir / "test_cases.md").read_text(encoding="utf-8")

        assert len(test_cases) == 2
        assert "Partial Coverage" in report
        assert "Action Status" in qa_report
        assert "requests 2.20.0" in report
        assert "Informational Header Observation" not in qa_report
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
