from __future__ import annotations

from typing import Any

_SEVERITY_RANK: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

_EXTERNALLY_EXPOSED_SOURCES = {"headers", "db", "server", "network", "ssl_labs", "shodan", "zap", "nuclei"}
_HIGH_IMPACT_CATEGORIES = {
    "auth",
    "admin-exposure",
    "db-credentials",
    "db-dump",
    "injection",
    "path-traversal",
    "secrets",
    "cve",
    "db-exposure",
    "directory-listing",
    "remote-access",
    "sensitive-file",
    "windows-exposure",
}


def prioritize(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply explainable, rule-based prioritization and sort ascending."""
    prioritized: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []

    for finding in findings:
        if finding.get("false_positive"):
            clone = dict(finding)
            clone["priority"] = 99
            clone["priority_reason"] = "Marked as false positive."
            false_positives.append(clone)
            continue

        clone = dict(finding)
        if "priority" in clone and clone.get("priority"):
            clone["priority_reason"] = clone.get("priority_reason", "Provided by upstream analysis.")
        else:
            priority, reason = _calculate_priority(clone)
            clone["priority"] = priority
            clone["priority_reason"] = reason
        prioritized.append(clone)

    prioritized.sort(key=lambda finding: (finding.get("priority", 99), _SEVERITY_RANK.get(finding.get("severity", "info"), 5)))
    false_positives.sort(key=lambda finding: finding.get("title", ""))
    return prioritized + false_positives


def _calculate_priority(finding: dict[str, Any]) -> tuple[int, str]:
    score = _SEVERITY_RANK.get(finding.get("severity", "info"), 5)
    reasons: list[str] = [f"base severity={finding.get('severity', 'info')}"]

    if _is_internet_exposed(finding):
        score -= 1
        reasons.append("internet exposed")

    if finding.get("category") in _HIGH_IMPACT_CATEGORIES:
        score -= 1
        reasons.append(f"high impact category={finding.get('category')}")

    if _is_reproducible(finding):
        score -= 1
        reasons.append("clear reproduction or evidence")

    evidence_adjustment, evidence_reasons = _evidence_priority_adjustment(finding)
    score += evidence_adjustment
    reasons.extend(evidence_reasons)

    dependency_adjustment, dependency_reasons = _dependency_priority_adjustment(finding)
    score += dependency_adjustment
    reasons.extend(dependency_reasons)

    if _has_fix_signal(finding):
        reasons.append("fix signal present")

    priority = min(max(score, 1), 5)
    return priority, ", ".join(reasons)


def _is_internet_exposed(finding: dict[str, Any]) -> bool:
    source = finding.get("source", "")
    location = str(finding.get("location", ""))
    raw = finding.get("raw", {}) or {}
    return (
        source in _EXTERNALLY_EXPOSED_SOURCES
        or location.startswith("http://")
        or location.startswith("https://")
        or bool(raw.get("ports"))
    )


def _is_reproducible(finding: dict[str, Any]) -> bool:
    reproduction = str(finding.get("reproduction_steps", "")).strip()
    evidence = str(finding.get("evidence", "")).strip()
    return bool(reproduction or evidence)


def _has_fix_signal(finding: dict[str, Any]) -> bool:
    raw = finding.get("raw", {}) or {}
    if str(finding.get("fix_suggestion", "")).strip():
        return True
    return bool(raw.get("fix_versions")) or bool(raw.get("fix_available"))


def _dependency_priority_adjustment(finding: dict[str, Any]) -> tuple[int, list[str]]:
    if finding.get("category") != "dependency":
        return 0, []

    raw = finding.get("raw", {}) or {}
    reasons: list[str] = []
    adjustment = 0
    is_direct = raw.get("is_direct")

    if is_direct is True:
        adjustment -= 1
        reasons.append("direct dependency")
    elif is_direct is False:
        adjustment += 1
        reasons.append("transitive dependency")

    if raw.get("fix_versions") or raw.get("fix_available"):
        adjustment -= 1
        reasons.append("ready fix path")
    else:
        reasons.append("no ready fix path")

    return adjustment, reasons


def _evidence_priority_adjustment(finding: dict[str, Any]) -> tuple[int, list[str]]:
    evidence_quality = finding.get("evidence_quality")
    if evidence_quality == "strong":
        return -1, ["strong evidence quality"]
    if evidence_quality == "weak":
        return 1, ["weak evidence quality"]
    if evidence_quality == "manual_check_required":
        return 1, ["manual evidence validation required"]
    if evidence_quality == "medium":
        return 0, ["medium evidence quality"]
    return 0, []
