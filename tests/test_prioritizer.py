from __future__ import annotations

from engine.prioritizer import prioritize


def _finding(
    severity: str,
    *,
    source: str = "semgrep",
    category: str = "other",
    location: str = "src/app.py:10",
    false_positive: bool = False,
    priority: int | None = None,
    evidence: str = "",
    raw: dict | None = None,
) -> dict:
    finding = {
        "id": f"{severity}-{source}-{category}",
        "title": "test",
        "severity": severity,
        "source": source,
        "category": category,
        "location": location,
        "evidence": evidence,
        "raw": raw or {},
        "false_positive": false_positive,
    }
    if priority is not None:
        finding["priority"] = priority
    return finding


def test_priority_preserved_if_set() -> None:
    result = prioritize([_finding("info", priority=1)])
    assert result[0]["priority"] == 1
    assert "Provided by upstream analysis" in result[0]["priority_reason"]


def test_false_positive_is_moved_to_the_end() -> None:
    result = prioritize([
        _finding("medium"),
        _finding("critical", false_positive=True),
    ])
    assert result[0]["false_positive"] is False
    assert result[-1]["false_positive"] is True
    assert result[-1]["priority"] == 99


def test_internet_exposed_finding_is_promoted() -> None:
    result = prioritize([
        _finding("high", source="semgrep", category="other"),
        _finding("high", source="headers", category="headers", location="https://example.com"),
    ])
    assert result[0]["source"] == "headers"


def test_high_impact_category_is_promoted() -> None:
    result = prioritize([
        _finding("high", category="other"),
        _finding("high", category="injection"),
    ])
    assert result[0]["category"] == "injection"


def test_evidence_promotes_reproducible_finding() -> None:
    result = prioritize([
        _finding("medium", evidence=""),
        _finding("medium", evidence="proof"),
    ])
    assert result[0]["evidence"] == "proof"


def test_unknown_severity_defaults_to_lowest_priority_bucket() -> None:
    result = prioritize([_finding("unknown")])
    assert result[0]["priority"] == 5


def test_empty_list() -> None:
    assert prioritize([]) == []


def test_direct_dependency_with_fix_is_promoted() -> None:
    result = prioritize([
        _finding(
            "medium",
            category="dependency",
            raw={"is_direct": True, "fix_versions": ["2.32.4"]},
        ),
        _finding(
            "medium",
            category="dependency",
            raw={"is_direct": False, "fix_versions": []},
        ),
    ])

    assert result[0]["raw"]["is_direct"] is True
    assert "ready fix path" in result[0]["priority_reason"]
    assert "transitive dependency" in result[1]["priority_reason"]


def test_strong_evidence_is_promoted_over_manual_check_required() -> None:
    result = prioritize([
        _finding("medium", evidence="proof", raw={}, source="zap", category="injection") | {"evidence_quality": "strong"},
        _finding("medium", evidence="", raw={}, source="shodan", category="exposure") | {"evidence_quality": "manual_check_required"},
    ])

    assert result[0]["evidence_quality"] == "strong"
    assert "strong evidence quality" in result[0]["priority_reason"]
    assert "manual evidence validation required" in result[1]["priority_reason"]
