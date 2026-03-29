from __future__ import annotations

from engine.delta import compare


def _finding(
    title: str,
    dedup_key: str | None = None,
    *,
    category: str = "headers",
    location: str = "http://example.com",
    false_positive: bool = False,
) -> dict:
    return {
        "id": f"id-{title}",
        "title": title,
        "source": "headers",
        "severity": "high",
        "cvss_score": None,
        "category": category,
        "location": location,
        "description": "",
        "evidence": "",
        "raw": {"dedup_key": dedup_key} if dedup_key else {},
        "priority": 2,
        "false_positive": false_positive,
        "action_status": "fix_now",
        "qa_verifiable": "qa_verifiable",
        "verification_status": "unverified",
        "evidence_quality": "strong",
        "reproduction_steps": "",
        "fix_suggestion": "",
        "priority_reason": "",
        "delta_status": None,
    }


# ── 기본 동작 ──────────────────────────────────────────────────────────────

def test_new_finding_not_in_baseline() -> None:
    current = [_finding("CSP Missing", "headers|http://example.com|csp")]
    baseline: list = []

    result = compare(current, baseline)

    assert len(result["new"]) == 1
    assert result["new"][0]["title"] == "CSP Missing"
    assert result["persisted"] == []
    assert result["fixed"] == []


def test_persisted_finding_in_both() -> None:
    key = "headers|http://example.com|csp"
    current = [_finding("CSP Missing", key)]
    baseline = [_finding("CSP Missing", key)]

    result = compare(current, baseline)

    assert result["new"] == []
    assert len(result["persisted"]) == 1
    assert result["persisted"][0]["title"] == "CSP Missing"
    assert result["fixed"] == []


def test_fixed_finding_only_in_baseline() -> None:
    key = "headers|http://example.com|csp"
    current: list = []
    baseline = [_finding("CSP Missing", key)]

    result = compare(current, baseline)

    assert result["new"] == []
    assert result["persisted"] == []
    assert len(result["fixed"]) == 1
    assert result["fixed"][0]["title"] == "CSP Missing"


def test_mixed_new_persisted_fixed() -> None:
    key_a = "headers|http://example.com|csp"
    key_b = "headers|http://example.com|hsts"
    key_c = "headers|http://example.com|xfo"

    current = [
        _finding("CSP Missing", key_a),   # persisted
        _finding("HSTS Missing", key_b),  # new
    ]
    baseline = [
        _finding("CSP Missing", key_a),   # persisted
        _finding("XFO Missing", key_c),   # fixed
    ]

    result = compare(current, baseline)

    assert len(result["new"]) == 1
    assert result["new"][0]["title"] == "HSTS Missing"

    assert len(result["persisted"]) == 1
    assert result["persisted"][0]["title"] == "CSP Missing"

    assert len(result["fixed"]) == 1
    assert result["fixed"][0]["title"] == "XFO Missing"


# ── baseline 없을 때 ────────────────────────────────────────────────────────

def test_empty_baseline_all_new() -> None:
    current = [
        _finding("CSP Missing", "key-a"),
        _finding("HSTS Missing", "key-b"),
    ]

    result = compare(current, [])

    assert len(result["new"]) == 2
    assert result["persisted"] == []
    assert result["fixed"] == []


def test_empty_current_all_fixed() -> None:
    baseline = [
        _finding("CSP Missing", "key-a"),
        _finding("HSTS Missing", "key-b"),
    ]

    result = compare([], baseline)

    assert result["new"] == []
    assert result["persisted"] == []
    assert len(result["fixed"]) == 2


def test_both_empty_returns_empty() -> None:
    result = compare([], [])

    assert result["new"] == []
    assert result["persisted"] == []
    assert result["fixed"] == []


# ── dedup_key 없는 finding 처리 ────────────────────────────────────────────

def test_finding_without_dedup_key_is_skipped() -> None:
    current = [
        _finding("No Key Finding", dedup_key=None),
        _finding("Has Key Finding", "key-a"),
    ]
    baseline: list = []

    result = compare(current, baseline)

    assert len(result["new"]) == 1
    assert result["new"][0]["title"] == "Has Key Finding"


def test_baseline_finding_without_dedup_key_is_skipped() -> None:
    current: list = []
    baseline = [
        _finding("No Key Finding", dedup_key=None),
        _finding("Has Key Baseline", "key-b"),
    ]

    result = compare(current, baseline)

    assert len(result["fixed"]) == 1
    assert result["fixed"][0]["title"] == "Has Key Baseline"


def test_all_findings_without_dedup_key_returns_empty() -> None:
    current = [_finding("A", dedup_key=None), _finding("B", dedup_key=None)]
    baseline = [_finding("C", dedup_key=None)]

    result = compare(current, baseline)

    assert result["new"] == []
    assert result["persisted"] == []
    assert result["fixed"] == []


# ── 중복 dedup_key 처리 ────────────────────────────────────────────────────

def test_duplicate_dedup_key_in_current_uses_first() -> None:
    key = "headers|http://example.com|csp"
    current = [
        _finding("CSP Finding 1", key),
        _finding("CSP Finding 2", key),
    ]

    result = compare(current, [])

    assert len(result["new"]) == 1
    assert result["new"][0]["title"] == "CSP Finding 1"
