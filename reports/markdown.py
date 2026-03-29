from __future__ import annotations

from pathlib import Path

from engine.qa_converter import QATestCase

_CATEGORY_GROUPS: dict[str, list[str]] = {
    "OWASP Top 10": ["injection", "xss", "csrf", "redirect", "path-traversal"],
    "Authentication": ["auth"],
    "Web Security": [
        "headers", "exposure", "default-page", "information-disclosure",
        "session", "clickjacking", "integrity",
    ],
    "Network And SSL": ["ssl", "cve", "network-exposure", "remote-access", "windows-exposure"],
    "Server Security": ["server-exposure", "sensitive-file", "admin-exposure", "directory-listing"],
    "Database Security": ["db-exposure", "db-dump", "db-credentials"],
    "Code And Dependency": ["dependency", "secrets", "semgrep"],
    "Other": ["other"],
}

_SEVERITY_BADGE = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]    ",
    "medium":   "[MEDIUM]  ",
    "low":      "[LOW]     ",
    "info":     "[INFO]    ",
}

_ACTION_BADGE = {
    "fix_now":       "🔴 Fix Now",
    "review_needed": "🟡 Review Needed",
    "backlog":       "🔵 Backlog",
}

_EVIDENCE_BADGE = {
    "strong":               "Strong",
    "medium":               "Medium",
    "weak":                 "Weak",
    "manual_check_required":"Manual Check Required",
}

_DELTA_BADGE = {
    "new":       "🆕 New",
    "persisted": "🔁 Persisted",
    "fixed":     "✅ Fixed",
}


def _get_group(category: str) -> str:
    for group, categories in _CATEGORY_GROUPS.items():
        if category in categories:
            return group
    return "Other"


def generate(
    test_cases: list[QATestCase],
    findings: list[dict],
    metadata: dict,
    output_dir: Path,
) -> None:
    (output_dir / "test_cases.md").write_text(
        _render_test_cases(test_cases, metadata),
        encoding="utf-8",
    )
    (output_dir / "report_dev.md").write_text(
        _render_report_dev(test_cases, findings, metadata),
        encoding="utf-8",
    )


def _render_test_cases(test_cases: list[QATestCase], metadata: dict) -> str:
    target = metadata.get("target", "unknown")
    scanned_at = metadata.get("scanned_at", "")[:10]
    ai_status = metadata.get("ai_status", "unknown")

    lines: list[str] = [
        "# QA Test Cases",
        "",
        f"**Target**: {target}  ",
        f"**Scanned At**: {scanned_at}  ",
        f"**AI Status**: {ai_status}  ",
        f"**Coverage**: {metadata.get('coverage_status', 'unknown')}  ",
        f"**Confidence**: {metadata.get('report_confidence', 'unknown')}  ",
        "",
    ]

    warning = _coverage_warning(metadata)
    if warning:
        lines.extend([warning, ""])

    if not test_cases:
        lines.append("No actionable QA test cases were generated.")
        return "\n".join(lines)

    grouped: dict[str, list[QATestCase]] = {}
    for test_case in test_cases:
        grouped.setdefault(_get_group(test_case["category"]), []).append(test_case)

    for group_name in _CATEGORY_GROUPS:
        if group_name not in grouped:
            continue
        lines.extend([f"## {group_name}", ""])
        for test_case in grouped[group_name]:
            lines.extend(_render_test_case(test_case))

    return "\n".join(lines)


def _render_test_case(test_case: QATestCase) -> list[str]:
    lines = [
        f"## {test_case['id']}: {test_case['title']}",
        "",
        f"**Severity**: {test_case['severity'].capitalize()} | **Priority**: {test_case['priority']} | **Category**: {test_case['category']}  ",
        f"**Action Status**: {_fmt_action(test_case['action_status'])}  ",
        f"**QA Verifiable**: {_fmt_qa(test_case['qa_verifiable'])} | **Verification Status**: {_fmt_verify(test_case['verification_status'])}  ",
        f"**Evidence Quality**: {_EVIDENCE_BADGE.get(test_case.get('evidence_quality', 'medium'), 'Medium')}  ",
        f"**Location**: `{test_case['location']}`",
        "",
    ]

    if test_case["reproduction_steps"]:
        lines.extend(["### Reproduction", "", test_case["reproduction_steps"], ""])

    if test_case["evidence"]:
        lines.extend(["### Evidence", "", "```", test_case["evidence"], "```", ""])

    if test_case["fix_suggestion"]:
        lines.extend(["### Fix Suggestion", "", test_case["fix_suggestion"], ""])

    lines.extend([
        "### QA Checklist",
        "",
        "- [ ] Verify the fix is applied",
        "- [ ] Confirm the issue is no longer reproducible",
        "",
        "---",
        "",
    ])
    return lines


def _render_report_dev(
    test_cases: list[QATestCase],
    findings: list[dict],
    metadata: dict,
) -> str:
    target = metadata.get("target", "unknown")
    scanned_at = metadata.get("scanned_at", "")[:10]
    scan_type = metadata.get("scan_type", "unknown")
    ai_status = metadata.get("ai_status", "unknown")
    ai_notes = metadata.get("ai_notes", "")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    action_counts = {"fix_now": 0, "review_needed": 0, "backlog": 0}
    verification_counts = {"unverified": 0, "reproduced": 0, "needs_manual_check": 0, "fixed_pending_retest": 0}
    evidence_counts = {"strong": 0, "medium": 0, "weak": 0, "manual_check_required": 0}
    for tc in test_cases:
        sev = tc["severity"]
        if sev in counts:
            counts[sev] += 1
        act = tc.get("action_status")
        if act in action_counts:
            action_counts[act] += 1
        ver = tc.get("verification_status")
        if ver in verification_counts:
            verification_counts[ver] += 1
        evq = tc.get("evidence_quality")
        if evq in evidence_counts:
            evidence_counts[evq] += 1

    false_positive_count = sum(1 for f in findings if f.get("false_positive"))
    total_findings = len(findings)
    failed_scanners = metadata.get("failed_scanners", [])
    coverage = metadata.get("coverage_status", "unknown")
    confidence = metadata.get("report_confidence", "unknown")

    # ── 헤더 ─────────────────────────────────────────────────────────
    lines: list[str] = [
        f"# Security QA Report — {target}",
        "",
        f"**Scanned**: {scanned_at}"
        f"  |  **Type**: {scan_type.upper()}"
        f"  |  **AI**: {ai_status.replace('_', ' ').title()}"
        f"  |  **Coverage**: {coverage.title()}"
        f"  |  **Confidence**: {confidence.title()}",
        "",
        "---",
        "",
    ]

    # ── 커버리지 경고 ─────────────────────────────────────────────────
    if coverage == "partial":
        lines.extend([
            f"> ⚠️ **Partial Coverage** — Failed scanners: `{', '.join(failed_scanners)}`",
            "",
        ])

    if ai_notes:
        lines.extend([f"> {ai_notes}", ""])

    # ── Delta 요약 (baseline 있을 때만) ──────────────────────────────
    delta_lines = _render_delta_summary(findings)
    if delta_lines:
        lines.extend(delta_lines)

    # ── 스캔 오버뷰 ───────────────────────────────────────────────────
    lines.extend([
        "## Scan Overview",
        "",
        "**Severity Breakdown**",
        "",
        "| Severity | Count |",
        "|----------|:-----:|",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| Info | {counts['info']} |",
        f"| **Actionable Total** | **{len(test_cases)}** |",
        "",
        "**Action Queue**",
        "",
        "| Action | Count |",
        "|--------|:-----:|",
        f"| 🔴 Fix Now | **{action_counts['fix_now']}** |",
        f"| 🟡 Review Needed | {action_counts['review_needed']} |",
        f"| 🔵 Backlog | {action_counts['backlog']} |",
        "",
        f"> Total raw findings: {total_findings} &nbsp;|&nbsp; False positives removed: {false_positive_count}",
        "",
        "---",
        "",
    ])

    if not test_cases:
        lines.append("No actionable findings remain after filtering.")
        return "\n".join(lines)

    # ── 도메인 커버리지 ───────────────────────────────────────────────
    group_counts: dict[str, int] = {}
    for tc in test_cases:
        g = _get_group(tc["category"])
        group_counts[g] = group_counts.get(g, 0) + 1

    lines.extend([
        "## Domain Coverage",
        "",
        "| Domain | Findings | Status |",
        "|--------|:--------:|--------|",
    ])
    for group_name in _CATEGORY_GROUPS:
        count = group_counts.get(group_name, 0)
        if count > 0:
            status = "⚠️ Needs Review"
        else:
            status = "✅ No Actionable Finding"
        lines.append(f"| {group_name} | {count if count else '—'} | {status} |")

    lines.extend(["", "---", ""])

    # ── finding별 카드 렌더 함수 ──────────────────────────────────────
    finding_by_id = {f.get("id"): f for f in findings}

    def render_finding_card(tc: QATestCase) -> list[str]:
        finding = finding_by_id.get(tc["source_finding_id"], {})
        sev_badge = _SEVERITY_BADGE.get(tc["severity"], tc["severity"].upper())
        group = _get_group(tc["category"])
        delta_status = finding.get("delta_status")
        delta_badge = _DELTA_BADGE.get(delta_status, "") if delta_status else ""

        title_suffix = f" {delta_badge}" if delta_badge else ""
        card: list[str] = [
            f"### {tc['id']} — {tc['title']}{title_suffix}",
            "",
            f"| | |",
            f"|---|---|",
            f"| **Severity** | `{sev_badge.strip()}` |",
            f"| **Area** | {group} |",
            f"| **Location** | `{tc['location']}` |",
            f"| **Evidence Quality** | {_EVIDENCE_BADGE.get(tc.get('evidence_quality', 'medium'), 'Medium')} |",
            f"| **QA Verifiable** | {_fmt_qa(tc['qa_verifiable'])} |",
        ]
        if delta_badge:
            card.append(f"| **Delta** | {delta_badge} |")
        card.append("")

        reason = finding.get("priority_reason", "")
        if reason:
            card.extend([f"> {reason}", ""])

        if tc["reproduction_steps"]:
            card.extend([
                "**재현 방법**",
                "",
                tc["reproduction_steps"],
                "",
            ])

        if tc["fix_suggestion"]:
            card.extend([
                "**수정 방법**",
                "",
                tc["fix_suggestion"],
                "",
            ])

        evidence = tc.get("evidence", "")
        if evidence:
            card.extend([
                "**증거**",
                "",
                "```",
                evidence,
                "```",
                "",
            ])

        card.extend(["---", ""])
        return card

    # ── Fix Now 섹션 ──────────────────────────────────────────────────
    fix_now = [tc for tc in test_cases if tc.get("action_status") == "fix_now"]
    if fix_now:
        lines.extend([
            f"## 🔴 Fix Now ({len(fix_now)})",
            "",
            "> 즉시 조치가 필요한 항목입니다.",
            "",
        ])
        for tc in fix_now:
            lines.extend(render_finding_card(tc))

    # ── Review Needed 섹션 ────────────────────────────────────────────
    review = [tc for tc in test_cases if tc.get("action_status") == "review_needed"]
    if review:
        lines.extend([
            f"## 🟡 Review Needed ({len(review)})",
            "",
            "> 검토 후 처리 여부를 결정해야 하는 항목입니다.",
            "",
        ])
        for tc in review:
            lines.extend(render_finding_card(tc))

    # ── Backlog 섹션 ──────────────────────────────────────────────────
    backlog = [tc for tc in test_cases if tc.get("action_status") == "backlog"]
    if backlog:
        lines.extend([
            f"## 🔵 Backlog ({len(backlog)})",
            "",
            "> 낮은 위험도 항목. 향후 개선 시 반영을 권장합니다.",
            "",
        ])
        for tc in backlog:
            lines.extend(render_finding_card(tc))

    return "\n".join(lines)


def _render_delta_summary(findings: list[dict]) -> list[str]:
    delta_counts = {"new": 0, "persisted": 0, "fixed": 0}
    has_delta = False
    for f in findings:
        status = f.get("delta_status")
        if status in delta_counts:
            delta_counts[status] += 1
            has_delta = True

    if not has_delta:
        return []

    return [
        "## Delta Summary",
        "",
        "| Status | Count |",
        "|--------|:-----:|",
        f"| 🆕 New | {delta_counts['new']} |",
        f"| 🔁 Persisted | {delta_counts['persisted']} |",
        f"| ✅ Fixed | {delta_counts['fixed']} |",
        "",
        "---",
        "",
    ]


def _coverage_warning(metadata: dict) -> str:
    status = metadata.get("coverage_status")
    failed = metadata.get("failed_scanners", [])
    if status == "partial":
        return f"> Warning: partial scan coverage. Failed scanners: {', '.join(failed) or 'unknown'}."
    if status == "failed":
        return f"> Warning: scan coverage is failed. Findings may be incomplete. Failed scanners: {', '.join(failed) or 'unknown'}."
    return ""


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _fmt_action(action_status: str) -> str:
    return _ACTION_BADGE.get(action_status, action_status)


def _fmt_qa(value: str) -> str:
    mapping = {
        "qa_verifiable": "QA Verifiable",
        "requires_dev_check": "Requires Dev Check",
        "requires_security_review": "Requires Security Review",
    }
    return mapping.get(value, value)


def _fmt_verify(value: str) -> str:
    mapping = {
        "unverified": "Unverified",
        "reproduced": "Reproduced",
        "needs_manual_check": "Needs Manual Check",
        "fixed_pending_retest": "Fixed Pending Retest",
    }
    return mapping.get(value, value)


# 하위 호환 — 기존 코드에서 직접 호출하는 경우 대비
def _format_action_status(action_status: str) -> str:
    return _fmt_action(action_status)


def _format_qa_verifiable(value: str) -> str:
    return _fmt_qa(value)


def _format_verification_status(value: str) -> str:
    return _fmt_verify(value)


def _format_evidence_quality(value: str) -> str:
    return _EVIDENCE_BADGE.get(value, value)
