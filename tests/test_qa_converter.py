from __future__ import annotations

from engine.qa_converter import convert, _rank_to_priority


def _finding(title: str, priority: int = 2, false_positive: bool = False) -> dict:
    return {
        "id": f"f-{title}",
        "title": title,
        "severity": "high",
        "category": "injection",
        "source": "zap",
        "location": "https://example.com",
        "priority": priority,
        "false_positive": false_positive,
        "action_status": "fix_now",
        "qa_verifiable": "qa_verifiable",
        "verification_status": "unverified",
        "evidence_quality": "strong",
        "reproduction_steps": "step 1",
        "fix_suggestion": "fix it",
        "evidence": "evidence",
    }


def test_false_positive_excluded():
    findings = [_finding("vuln1"), _finding("fp", false_positive=True)]
    result = convert(findings)
    assert len(result) == 1
    assert result[0]["title"] == "vuln1"


def test_tc_id_sequential():
    findings = [_finding("a"), _finding("b"), _finding("c")]
    result = convert(findings)
    assert [tc["id"] for tc in result] == ["TC-001", "TC-002", "TC-003"]


def test_tc_id_skips_false_positives():
    findings = [_finding("a"), _finding("fp", false_positive=True), _finding("b")]
    result = convert(findings)
    assert result[0]["id"] == "TC-001"
    assert result[1]["id"] == "TC-002"


def test_priority_p1():
    findings = [_finding("vuln", priority=1)]
    result = convert(findings)
    assert result[0]["priority"] == "P1"


def test_priority_p2():
    findings = [_finding("vuln", priority=3)]
    result = convert(findings)
    assert result[0]["priority"] == "P2"


def test_priority_p3():
    findings = [_finding("vuln", priority=5)]
    result = convert(findings)
    assert result[0]["priority"] == "P3"


def test_rank_to_priority_boundaries():
    assert _rank_to_priority(1) == "P1"
    assert _rank_to_priority(2) == "P1"
    assert _rank_to_priority(3) == "P2"
    assert _rank_to_priority(4) == "P3"
    assert _rank_to_priority(5) == "P3"


def test_fields_mapped_correctly():
    findings = [_finding("SQL Injection", priority=1)]
    tc = convert(findings)[0]
    assert tc["title"] == "SQL Injection"
    assert tc["action_status"] == "fix_now"
    assert tc["qa_verifiable"] == "qa_verifiable"
    assert tc["verification_status"] == "unverified"
    assert tc["evidence_quality"] == "strong"
    assert tc["reproduction_steps"] == "step 1"
    assert tc["fix_suggestion"] == "fix it"
    assert tc["evidence"] == "evidence"
    assert tc["source_finding_id"] == "f-SQL Injection"


def test_defaults_for_dev_check_sources():
    findings = [{
        "id": "f-dep",
        "title": "requests vuln",
        "severity": "medium",
        "source": "dependency",
        "category": "dependency",
        "location": "requirements.txt",
        "priority": 3,
        "false_positive": False,
        "evidence": "",
        "reproduction_steps": "",
        "fix_suggestion": "",
    }]
    tc = convert(findings)[0]
    assert tc["qa_verifiable"] == "requires_dev_check"
    assert tc["verification_status"] == "needs_manual_check"
    assert tc["evidence_quality"] == "weak"


def test_empty_input():
    assert convert([]) == []


def test_all_false_positives():
    findings = [_finding("x", false_positive=True), _finding("y", false_positive=True)]
    assert convert(findings) == []
