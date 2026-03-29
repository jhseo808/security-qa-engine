from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Literal, TypedDict


Severity = Literal["critical", "high", "medium", "low", "info"]
CoverageStatus = Literal["complete", "partial", "failed"]
ReportConfidence = Literal["high", "medium", "low"]
AIStatus = Literal["completed", "skipped", "fallback", "manual_required"]
ActionStatus = Literal["fix_now", "backlog", "review_needed"]
QAVerifiable = Literal["qa_verifiable", "requires_dev_check", "requires_security_review"]
VerificationStatus = Literal["unverified", "reproduced", "needs_manual_check", "fixed_pending_retest"]
EvidenceQuality = Literal["strong", "medium", "weak", "manual_check_required"]
DeltaStatus = Literal["new", "persisted", "fixed"]


class Finding(TypedDict):
    id: str
    source: str
    title: str
    severity: Severity
    cvss_score: float | None
    category: str
    location: str
    description: str
    evidence: str
    raw: dict


class CoverageSummary(TypedDict):
    expected_scanners: list[str]
    executed_scanners: list[str]
    failed_scanners: list[str]
    coverage_status: CoverageStatus
    report_confidence: ReportConfidence


class ScanResult(TypedDict):
    scan_id: str
    scan_type: str
    target: str
    scanned_at: str
    scanners_run: list[str]
    scanners_failed: list[str]
    expected_scanners: list[str]
    executed_scanners: list[str]
    failed_scanners: list[str]
    coverage_status: CoverageStatus
    report_confidence: ReportConfidence
    findings: list[Finding]


class FilteredFinding(TypedDict):
    id: str
    source: str
    title: str
    severity: Severity
    cvss_score: float | None
    category: str
    location: str
    description: str
    evidence: str
    raw: dict
    priority: int
    false_positive: bool
    action_status: ActionStatus
    qa_verifiable: QAVerifiable
    verification_status: VerificationStatus
    evidence_quality: EvidenceQuality
    reproduction_steps: str
    fix_suggestion: str
    priority_reason: str
    delta_status: DeltaStatus | None


class FilteredResult(TypedDict):
    scan_id: str
    scan_type: str
    target: str
    scanned_at: str
    filtered_at: str
    ai_status: AIStatus
    ai_notes: str
    scanners_run: list[str]
    scanners_failed: list[str]
    expected_scanners: list[str]
    executed_scanners: list[str]
    failed_scanners: list[str]
    coverage_status: CoverageStatus
    report_confidence: ReportConfidence
    findings: list[FilteredFinding]


def make_finding(
    source: str,
    title: str,
    severity: Severity,
    category: str,
    location: str,
    description: str,
    evidence: str = "",
    cvss_score: float | None = None,
    raw: dict | None = None,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        source=source,
        title=title,
        severity=severity,
        cvss_score=cvss_score,
        category=category,
        location=location,
        description=description,
        evidence=evidence,
        raw=raw or {},
    )


def build_coverage_summary(
    expected_scanners: list[str],
    scanners_run: list[str],
    scanners_failed: list[str],
) -> CoverageSummary:
    expected = list(dict.fromkeys(expected_scanners))
    executed = list(dict.fromkeys(scanners_run))
    failed = list(dict.fromkeys(scanners_failed))

    if not executed and failed:
        coverage_status: CoverageStatus = "failed"
        report_confidence: ReportConfidence = "low"
    elif failed:
        coverage_status = "partial"
        report_confidence = "medium" if executed else "low"
    else:
        coverage_status = "complete"
        report_confidence = "high"

    return CoverageSummary(
        expected_scanners=expected,
        executed_scanners=executed,
        failed_scanners=failed,
        coverage_status=coverage_status,
        report_confidence=report_confidence,
    )


def build_scan_result(
    target: str,
    scan_type: str,
    findings: list[Finding],
    scanners_run: list[str],
    scanners_failed: list[str],
    expected_scanners: list[str],
) -> ScanResult:
    deduplicated_findings = deduplicate_findings(findings)
    coverage = build_coverage_summary(expected_scanners, scanners_run, scanners_failed)
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type=scan_type,
        target=target,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        scanners_run=scanners_run,
        scanners_failed=scanners_failed,
        expected_scanners=coverage["expected_scanners"],
        executed_scanners=coverage["executed_scanners"],
        failed_scanners=coverage["failed_scanners"],
        coverage_status=coverage["coverage_status"],
        report_confidence=coverage["report_confidence"],
        findings=deduplicated_findings,
    )


def to_filtered_findings(findings: list[Finding]) -> list[FilteredFinding]:
    result: list[FilteredFinding] = []
    for finding in findings:
        false_positive, priority_reason = _default_false_positive_state(finding)
        result.append(FilteredFinding(
            id=finding["id"],
            source=finding["source"],
            title=finding["title"],
            severity=finding["severity"],
            cvss_score=finding["cvss_score"],
            category=finding["category"],
            location=finding["location"],
            description=finding["description"],
            evidence=finding["evidence"],
            raw=finding["raw"],
            priority=5,
            false_positive=false_positive,
            action_status=_default_action_status(finding),
            qa_verifiable=_default_qa_verifiable(finding),
            verification_status=_default_verification_status(finding),
            evidence_quality=_default_evidence_quality(finding),
            reproduction_steps=_default_reproduction_steps(finding),
            fix_suggestion=_default_fix_suggestion(finding),
            priority_reason=priority_reason,
            delta_status=None,
        ))
    return result


def build_filtered_result(
    scan_result: ScanResult,
    findings: list[FilteredFinding],
    ai_status: AIStatus,
    ai_notes: str,
) -> FilteredResult:
    return FilteredResult(
        scan_id=scan_result["scan_id"],
        scan_type=scan_result["scan_type"],
        target=scan_result["target"],
        scanned_at=scan_result["scanned_at"],
        filtered_at=datetime.now(timezone.utc).isoformat(),
        ai_status=ai_status,
        ai_notes=ai_notes,
        scanners_run=scan_result["scanners_run"],
        scanners_failed=scan_result["scanners_failed"],
        expected_scanners=scan_result["expected_scanners"],
        executed_scanners=scan_result["executed_scanners"],
        failed_scanners=scan_result["failed_scanners"],
        coverage_status=scan_result["coverage_status"],
        report_confidence=scan_result["report_confidence"],
        findings=findings,
    )


_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "set-cookie",
]

_COMMON_WEB_PORTS = {80, 443}
_CRITICAL_NETWORK_PORTS = {6379, 9200, 27017}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = {}
    ordered_keys: list[str] = []

    for finding in findings:
        key = _dedup_key(finding)
        if key not in groups:
            groups[key] = []
            ordered_keys.append(key)
        groups[key].append(finding)

    result: list[Finding] = []
    for key in ordered_keys:
        group = groups[key]
        if len(group) == 1:
            result.append(group[0])
            continue
        result.append(_merge_findings(group, key))
    return result


_ZAP_RISK_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

_CWE_CATEGORY_MAP = {
    "79": "xss",
    "89": "injection",
    "22": "path-traversal",
    "200": "exposure",
    "352": "csrf",
    "601": "redirect",
}


def normalize_zap(alerts: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        severity = _ZAP_RISK_MAP.get(risk, "info")
        cwe = str(alert.get("cweid", ""))
        category = _CWE_CATEGORY_MAP.get(cwe, "other")
        findings.append(make_finding(
            source="zap",
            title=alert.get("alert", "Unknown Alert"),
            severity=severity,
            category=category,
            location=alert.get("url", ""),
            description=alert.get("description", ""),
            evidence=alert.get("evidence", ""),
            cvss_score=_parse_cvss(alert.get("riskdesc", "")),
            raw=alert,
        ))
    return findings


def normalize_headers(issues: list[dict]) -> list[Finding]:
    return [
        make_finding(
            source="headers",
            title=issue["title"],
            severity=issue["severity"],
            category="headers",
            location=issue["url"],
            description=issue["description"],
            evidence=issue.get("evidence", ""),
            raw=issue,
        )
        for issue in issues
    ]


def normalize_server(issues: list[dict]) -> list[Finding]:
    return [
        make_finding(
            source="server",
            title=issue["title"],
            severity=issue["severity"],
            category=issue.get("category", "server-exposure"),
            location=issue["url"],
            description=issue["description"],
            evidence=issue.get("evidence", ""),
            raw=issue,
        )
        for issue in issues
    ]


def normalize_db(issues: list[dict]) -> list[Finding]:
    return [
        make_finding(
            source="db",
            title=issue["title"],
            severity=issue["severity"],
            category=issue.get("category", "db-exposure"),
            location=issue["url"],
            description=issue["description"],
            evidence=issue.get("evidence", ""),
            raw=issue,
        )
        for issue in issues
    ]


def normalize_network(result: dict) -> list[Finding]:
    if not result:
        return []

    host = result.get("host", "")
    services = result.get("services", [])
    findings: list[Finding] = []

    extra_services = [service for service in services if int(service.get("port", 0)) not in _COMMON_WEB_PORTS]
    risky_services = [service for service in services if _network_service_classification(service) is not None]

    if extra_services:
        severity: Severity = "high" if risky_services else "medium"
        findings.append(make_finding(
            source="network",
            title="Additional externally reachable services detected",
            severity=severity,
            category="network-exposure",
            location=host,
            description=(
                "The target exposes non-web services to the network. "
                "Review whether each service must be publicly reachable."
            ),
            evidence=", ".join(_service_signature(service) for service in extra_services),
            raw={
                "host": host,
                "ports": [service.get("port") for service in extra_services],
                "services": extra_services,
                "service_count": len(extra_services),
            },
        ))

    for service in risky_services:
        classification = _network_service_classification(service)
        if classification is None:
            continue

        port = int(service.get("port", 0))
        service_name = service.get("service", "unknown")
        findings.append(make_finding(
            source="network",
            title=classification["title"].format(service=service_name, port=port),
            severity=classification["severity"],
            category=classification["category"],
            location=f"{host}:{port}/{service.get('protocol', 'tcp')}",
            description=classification["description"].format(service=service_name, port=port),
            evidence=_service_signature(service),
            raw={
                "host": host,
                **service,
            },
        ))

    return findings


def _parse_cvss(riskdesc: str) -> float | None:
    return None


_NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def normalize_nuclei(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        info = result.get("info", {})
        severity = _NUCLEI_SEVERITY_MAP.get(info.get("severity", "info"), "info")
        template_id = result.get("template-id", "")
        category = template_id.split("/")[0] if "/" in template_id else "other"
        findings.append(make_finding(
            source="nuclei",
            title=info.get("name", template_id),
            severity=severity,
            category=category,
            location=result.get("matched-at", result.get("host", "")),
            description=info.get("description", ""),
            evidence=str(result.get("extracted-results", "")),
            raw=result,
        ))
    return findings


_SSL_GRADE_SEVERITY = {
    "A+": "info",
    "A": "info",
    "A-": "info",
    "B": "low",
    "C": "medium",
    "D": "medium",
    "E": "high",
    "F": "high",
    "T": "high",
    "M": "high",
}


def normalize_ssl_labs(result: dict) -> list[Finding]:
    if not result:
        return []

    findings: list[Finding] = []
    host = result.get("host", "")

    for endpoint in result.get("endpoints", []):
        grade = endpoint.get("grade", "")
        severity = _SSL_GRADE_SEVERITY.get(grade, "info")
        ip = endpoint.get("ipAddress", "")

        if grade not in ("A+", "A", "A-"):
            findings.append(make_finding(
                source="ssl_labs",
                title=f"SSL/TLS grade: {grade} ({host})",
                severity=severity,
                category="ssl",
                location=f"https://{host} ({ip})",
                description=f"SSL Labs rated the endpoint as {grade}. A or better is recommended.",
                evidence=f"Grade: {grade}, IP: {ip}",
                raw=endpoint,
            ))

        details = endpoint.get("details", {})
        for proto in details.get("protocols", []):
            proto_name = f"{proto.get('name', '')} {proto.get('version', '')}".strip()
            if proto.get("name") == "SSL" or proto.get("version") in ("2.0", "3.0"):
                findings.append(make_finding(
                    source="ssl_labs",
                    title=f"Legacy protocol enabled: {proto_name}",
                    severity="high",
                    category="ssl",
                    location=f"https://{host}",
                    description=f"{proto_name} is outdated and should be disabled.",
                    evidence=proto_name,
                    raw=proto,
                ))

    return findings


def normalize_shodan(result: dict) -> list[Finding]:
    if not result:
        return []

    findings: list[Finding] = []
    ip = result.get("ip_str", "")
    hostnames = ", ".join(result.get("hostnames", []))
    location = f"{ip} ({hostnames})" if hostnames else ip

    ports = result.get("ports", [])
    if ports:
        findings.append(make_finding(
            source="shodan",
            title=f"Exposed ports: {', '.join(map(str, ports))}",
            severity="info",
            category="exposure",
            location=location,
            description=f"Internet-exposed ports reported by Shodan: {ports}",
            evidence=str(ports),
            raw={"ports": ports},
        ))

    for cve_id, cve_info in result.get("vulns", {}).items():
        cvss = cve_info.get("cvss", 0.0)
        score = float(cvss) if cvss else 0.0
        findings.append(make_finding(
            source="shodan",
            title=f"{cve_id}: {cve_info.get('summary', '')[:80]}",
            severity=_cvss_to_severity(score),
            category="cve",
            location=location,
            description=cve_info.get("summary", ""),
            evidence=f"CVSS: {cvss}",
            cvss_score=score if cvss else None,
            raw=cve_info,
        ))

    return findings


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


_SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def normalize_semgrep(result: dict) -> list[Finding]:
    findings: list[Finding] = []
    for item in result.get("results", []):
        severity = _SEMGREP_SEVERITY_MAP.get(
            item.get("extra", {}).get("severity", "INFO"),
            "low",
        )
        meta = item.get("extra", {}).get("metadata", {})
        category = meta.get("category", "other")
        start = item.get("start", {})
        path = item.get("path", "")
        line = start.get("line", "")
        location = f"{path}:{line}" if line else path
        findings.append(make_finding(
            source="semgrep",
            title=item.get("check_id", "Unknown Rule"),
            severity=severity,
            category=category,
            location=location,
            description=item.get("extra", {}).get("message", ""),
            evidence=item.get("extra", {}).get("lines", ""),
            raw=item,
        ))
    return findings


_NPM_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "low": "low",
    "info": "info",
}


def normalize_dependency(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        source = result.get("source", "dependency")
        if source == "pip-audit":
            fix = ", ".join(result.get("fix_versions", [])) or "none"
            aliases = ", ".join(result.get("aliases", [])) or "n/a"
            package = result.get("package", "")
            version = result.get("version", "")
            direct = result.get("is_direct")
            severity = _severity_from_dependency_result(result, default="high")
            findings.append(make_finding(
                source="dependency",
                title=f"{result.get('vuln_id', '')}: {package} {version}",
                severity=severity,
                category="dependency",
                location=f"requirements.txt ({package}=={version})",
                description=_build_dependency_description(result),
                evidence=f"Fix versions: {fix} | aliases: {aliases} | direct dependency: {direct}",
                raw=result,
                cvss_score=_extract_dependency_cvss(result),
            ))
        elif source == "npm-audit":
            severity = _NPM_SEVERITY_MAP.get(result.get("severity", "low"), "low")
            package = result.get("package", "")
            direct = result.get("is_direct")
            fix_available = result.get("fix_available", False)
            title = result.get("description", "")[:80]
            findings.append(make_finding(
                source="dependency",
                title=f"{package}: {title}",
                severity=severity,
                category="dependency",
                location=f"package.json ({package})",
                description=_build_dependency_description(result),
                evidence=(
                    f"via: {', '.join(result.get('via', []))} | "
                    f"fix available: {fix_available} | direct dependency: {direct}"
                ),
                raw=result,
                cvss_score=_extract_dependency_cvss(result),
            ))
        elif source == "grype":
            package = result.get("package", "")
            version = result.get("version", "")
            vuln_id = result.get("vuln_id", "")
            fix = ", ".join(result.get("fix_versions", [])) or "none"
            direct = result.get("is_direct")
            severity = _NUCLEI_SEVERITY_MAP.get(result.get("severity", "unknown"), "info")
            findings.append(make_finding(
                source="dependency",
                title=f"{vuln_id}: {package} {version}",
                severity=severity,
                category="dependency",
                location=f"WEB-INF/lib ({package}=={version})",
                description=result.get("description", "") or f"{vuln_id} in {package} {version}",
                evidence=f"Fix versions: {fix} | direct: {direct} | {', '.join(result.get('urls', [])[:2])}",
                raw=result,
                cvss_score=result.get("cvss_score"),
            ))
    return findings


def normalize_sbom(result: dict) -> list[Finding]:
    """sbom.py 결과를 Finding 리스트로 정규화한다."""
    findings: list[Finding] = []

    for item in result.get("findings", []):
        source = item.get("source", "")

        if source == "grype":
            findings.extend(normalize_dependency([item]))

        elif source == "webxml":
            severity = _NUCLEI_SEVERITY_MAP.get(item.get("severity", "medium"), "medium")
            check = item.get("check", "webxml")
            findings.append(make_finding(
                source="webxml",
                title=f"web.xml: {check}",
                severity=severity,
                category="server",
                location=item.get("location", "WEB-INF/web.xml"),
                description=item.get("description", ""),
                evidence=item.get("evidence", ""),
                raw=item,
            ))

    return findings


def normalize_secrets(result: dict) -> list[Finding]:
    findings: list[Finding] = []
    for file_path, secrets in result.get("results", {}).items():
        for secret in secrets:
            findings.append(make_finding(
                source="secrets",
                title=f"Secret detected: {secret.get('type', 'Unknown')}",
                severity="high",
                category="secrets",
                location=f"{file_path}:{secret.get('line_number', '')}",
                description=(
                    f"{secret.get('type', 'Unknown')} appears to be hardcoded in source. "
                    "Rotate the secret and remove it from version control history."
                ),
                evidence=f"Line {secret.get('line_number', '')}, hashed: {secret.get('hashed_secret', '')}",
                raw=secret,
            ))
    return findings


def _default_action_status(finding: Finding) -> ActionStatus:
    severity = finding["severity"]
    raw = finding.get("raw", {}) or {}

    if severity in {"critical", "high"}:
        return "fix_now"
    if finding.get("category") == "dependency":
        has_fix_signal = bool(raw.get("fix_versions")) or bool(raw.get("fix_available"))
        is_direct = raw.get("is_direct")
        if severity == "medium" and has_fix_signal and is_direct is True:
            return "fix_now"
        if severity == "medium":
            return "review_needed"
        if has_fix_signal and is_direct is True:
            return "review_needed"
        if is_direct is False and not has_fix_signal:
            return "backlog"
    if severity == "medium":
        return "review_needed"
    return "backlog"


def _default_qa_verifiable(finding: Finding) -> QAVerifiable:
    source = finding.get("source", "")
    category = finding.get("category", "")

    if source in {"headers", "db", "server", "network", "zap", "nuclei", "ssl_labs", "secrets"}:
        return "qa_verifiable"
    if source == "shodan" or category == "cve":
        return "requires_security_review"
    if source in {"semgrep", "dependency"} or category in {"dependency", "semgrep"}:
        return "requires_dev_check"
    return "qa_verifiable"


def _default_verification_status(finding: Finding) -> VerificationStatus:
    if _default_qa_verifiable(finding) == "qa_verifiable":
        return "unverified"
    return "needs_manual_check"


def _default_evidence_quality(finding: Finding) -> EvidenceQuality:
    source = finding.get("source", "")
    severity = finding.get("severity", "info")
    evidence = str(finding.get("evidence", "")).strip()
    raw = finding.get("raw", {}) or {}

    if source == "shodan":
        return "manual_check_required"

    if source in {"headers", "db", "server", "network", "ssl_labs", "secrets"}:
        return "strong" if evidence else "medium"

    if source in {"zap", "nuclei"}:
        if evidence:
            return "strong"
        return "medium"

    if source == "semgrep":
        return "medium" if evidence else "weak"

    if source == "dependency":
        if raw.get("fix_versions") or raw.get("fix_available") or raw.get("cvss_score") or raw.get("cvss"):
            return "medium"
        return "weak" if severity in {"low", "info"} else "medium"

    return "medium" if evidence else "weak"


def _default_false_positive_state(finding: Finding) -> tuple[bool, str]:
    source = finding.get("source", "")
    severity = finding.get("severity", "info")
    title = str(finding.get("title", "")).lower()
    evidence = str(finding.get("evidence", "")).strip()
    raw = finding.get("raw", {}) or {}

    if source == "shodan" and finding.get("category") == "exposure":
        return True, "Marked as false positive by fallback rules: informational external exposure inventory."

    if source == "headers":
        if severity == "low" and _is_optional_header_observation(title):
            return True, "Marked as false positive by fallback rules: optional low-signal header observation."
        if severity == "low" and not evidence:
            return True, "Marked as false positive by fallback rules: low-severity header issue without supporting evidence."

    if source == "dependency":
        if severity == "info" and not raw.get("fix_versions") and not raw.get("fix_available"):
            return True, "Marked as false positive by fallback rules: informational dependency issue without remediation path."

    if source == "ssl_labs" and severity == "info":
        return True, "Marked as false positive by fallback rules: informational TLS observation only."

    return False, "Baseline fallback before prioritization."


def _default_reproduction_steps(finding: Finding) -> str:
    source = finding.get("source", "")
    location = str(finding.get("location", "")).strip()
    title = str(finding.get("title", "")).strip()
    evidence = str(finding.get("evidence", "")).strip()
    description = str(finding.get("description", "")).strip()
    category = str(finding.get("category", "")).strip()

    if source == "headers":
        return "\n".join([
            f"1. Open `{location}` in a browser or send a GET request with curl.",
            "2. Inspect the response headers.",
            f"3. Confirm the reported header issue: {title}.",
            f"4. Compare the observed response with the expected secure header policy.",
        ])

    if source == "server":
        return "\n".join([
            f"1. Request `{location}` directly with a browser or curl.",
            "2. Confirm the HTTP status code and response body shown by the server.",
            f"3. Verify the reported server exposure condition: {title}.",
            f"4. Capture the page content or headers and compare them with the evidence: {evidence or description or 'server response'}.",
        ])

    if source == "db":
        return "\n".join([
            f"1. Request `{location}` directly with a browser or curl.",
            "2. Confirm the file content, JavaScript payload, or page source returned by the application.",
            f"3. Verify the reported database-related exposure: {title}.",
            f"4. Capture the exposed dump content or connection material and compare it with the evidence: {evidence or description or 'database exposure output'}.",
        ])

    if source == "network":
        return "\n".join([
            f"1. Resolve the target host and confirm the exposed service at `{location}`.",
            "2. Re-run a targeted port scan or connect with a service-appropriate client such as nc, telnet, or nmap.",
            f"3. Confirm the externally reachable service or port described by the finding: {title}.",
            f"4. Capture the observed banner or service response and compare it with the evidence: {evidence or description or 'network scan output'}.",
        ])

    if source in {"zap", "nuclei"}:
        return "\n".join([
            f"1. Request `{location}` and reproduce the affected flow.",
            "2. Repeat the request with the same parameters or payload path used by the scanner.",
            f"3. Confirm the behavior described by the finding: {title}.",
            f"4. Capture the response and compare it with the evidence: {evidence or description or 'scanner output'}.",
        ])

    if source == "ssl_labs":
        return "\n".join([
            f"1. Check the TLS configuration for `{location}`.",
            "2. Re-run a TLS inspection with SSL Labs or OpenSSL.",
            f"3. Confirm the reported protocol or grade issue: {title}.",
            "4. Verify the affected protocol, cipher, or certificate setting is actually enabled.",
        ])

    if source == "secrets":
        return "\n".join([
            f"1. Open `{location}` in the repository.",
            "2. Review the referenced line and surrounding code.",
            f"3. Confirm the secret pattern matches the reported type: {title}.",
            "4. Validate whether the value is active, test-only, or already revoked.",
        ])

    if source == "semgrep":
        return "\n".join([
            f"1. Open `{location}` in the codebase.",
            "2. Review the exact line and surrounding function.",
            f"3. Confirm the insecure pattern reported by the rule: {title}.",
            f"4. Compare the code with the evidence or rule message: {evidence or description or 'rule output'}.",
        ])

    if source == "dependency":
        raw = finding.get("raw", {}) or {}
        package = raw.get("package", "the affected package")
        version = raw.get("version", "")
        package_text = f"{package} {version}".strip()
        return "\n".join([
            f"1. Inspect the dependency manifest at `{location}`.",
            f"2. Confirm that `{package_text}` is present in the project dependency tree.",
            "3. Verify whether it is a direct dependency or pulled transitively.",
            f"4. Check the advisory details and fix path described in the finding evidence: {evidence or description or 'dependency advisory'}.",
        ])

    if source == "shodan":
        return "\n".join([
            f"1. Review the external exposure data for `{location}`.",
            "2. Validate the exposed service or vulnerability with infrastructure or security owners.",
            f"3. Confirm whether the reported issue is still externally reachable: {title}.",
            "4. Escalate to security review if the exposure cannot be validated by QA alone.",
        ])

    if category == "cve":
        return "\n".join([
            f"1. Review the asset or endpoint at `{location}`.",
            "2. Confirm the affected software version and deployment context.",
            f"3. Validate whether the CVE conditions apply to the environment: {title}.",
            "4. Escalate for security review if exploitability cannot be verified in QA.",
        ])

    return "\n".join([
        f"1. Review the affected target at `{location}`.",
        f"2. Confirm the reported issue conditions for `{title}`.",
        f"3. Compare the observed behavior with the evidence: {evidence or description or 'scanner output'}.",
        "4. Record whether the issue is reproducible, requires developer confirmation, or needs security review.",
    ])


def _default_fix_suggestion(finding: Finding) -> str:
    source = finding.get("source", "")
    category = str(finding.get("category", "")).strip()
    title = str(finding.get("title", "")).strip()
    raw = finding.get("raw", {}) or {}

    if source == "headers":
        return _header_fix_suggestion(title)

    if source == "server":
        return _server_fix_suggestion(category, title)

    if source == "db":
        return _db_fix_suggestion(category, title)

    if source == "network":
        return _network_fix_suggestion(category, title, raw)

    if source in {"zap", "nuclei"}:
        return _web_fix_suggestion(category, title)

    if source == "ssl_labs":
        return (
            "Update the TLS configuration to disable legacy protocols and weak ciphers, "
            "and aim for an SSL Labs grade of A or better."
        )

    if source == "secrets":
        return (
            "Remove the secret from source control, rotate the credential immediately, "
            "and move secret management to environment variables or a secure vault."
        )

    if source == "semgrep":
        return _code_fix_suggestion(category, title)

    if source == "dependency":
        return _dependency_fix_suggestion(raw, title)

    if source == "shodan" or category == "cve":
        return (
            "Validate the exposure with infrastructure or security owners, restrict unnecessary public access, "
            "and patch or isolate the affected service before escalation closure."
        )

    return (
        "Apply the recommended secure configuration or code change, add a regression test if possible, "
        "and re-run the scan to confirm the issue is no longer reported."
    )


def _header_fix_suggestion(title: str) -> str:
    normalized = title.lower()
    if "hsts" in normalized or "strict-transport-security" in normalized:
        return "Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains where applicable."
    if "csp" in normalized or "content-security-policy" in normalized:
        return "Define a strict Content-Security-Policy that removes unsafe-inline and unsafe-eval and limits sources to trusted origins."
    if "x-frame-options" in normalized or "frame-ancestors" in normalized:
        return "Set X-Frame-Options to DENY or SAMEORIGIN and add a matching frame-ancestors CSP directive."
    if "x-content-type-options" in normalized:
        return "Set X-Content-Type-Options to nosniff on all application responses."
    if "referrer-policy" in normalized:
        return "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin or no-referrer."
    if "cookie" in normalized or "samesite" in normalized or "httponly" in normalized or "secure" in normalized:
        return "Set Secure, HttpOnly, and an explicit SameSite policy on sensitive cookies, and keep SameSite=None paired with Secure."
    return "Add the missing security header or tighten the weak header value to match the application's secure baseline."


def _web_fix_suggestion(category: str, title: str) -> str:
    if category == "injection":
        return "Use parameterized queries or safe command execution APIs, validate server-side input, and remove unsafe string concatenation."
    if category == "xss":
        return "Apply output encoding, avoid unsafe HTML rendering, and enforce a restrictive Content-Security-Policy."
    if category == "csrf":
        return "Add CSRF tokens to state-changing requests and verify Origin or Referer where appropriate."
    if category == "path-traversal":
        return "Normalize and validate file paths against an allowlist and prevent user-controlled path traversal outside approved directories."
    if category == "redirect":
        return "Restrict redirects to an allowlist of trusted destinations and reject untrusted user-supplied redirect targets."
    if category == "auth":
        return "Tighten authentication and authorization checks on the affected endpoint and verify access control on the server side."
    return f"Review the affected web flow for `{title}` and apply the corresponding secure server-side validation or configuration fix."


def _code_fix_suggestion(category: str, title: str) -> str:
    if category == "injection":
        return "Refactor the affected code to avoid dangerous string interpolation and use safe APIs with strict input validation."
    if category == "secrets":
        return "Remove hardcoded credentials from the codebase and load secrets from secure runtime configuration."
    return f"Review the insecure pattern reported by `{title}`, replace it with the framework's recommended safe pattern, and add a regression test."


def _dependency_fix_suggestion(raw: dict, title: str) -> str:
    package = raw.get("package", "the affected package")
    version = raw.get("version", "")
    fix_versions = raw.get("fix_versions", [])
    fix_available = raw.get("fix_available")

    if fix_versions:
        fixes = ", ".join(str(item) for item in fix_versions)
        return f"Upgrade `{package}` from `{version}` to one of the fixed versions: {fixes}. Rebuild the dependency tree and rerun the scan."
    if fix_available:
        return f"Apply the available package manager fix for `{package}`, verify the lockfile changes, and rerun the dependency scan."
    return f"Review the advisory for `{title}`, determine whether `{package}` can be upgraded, replaced, or isolated, and track the mitigation if no fix is currently available."


def _is_optional_header_observation(title: str) -> bool:
    return any(
        token in title
        for token in (
            "permissions-policy",
            "referrer-policy",
        )
    )


def _network_fix_suggestion(category: str, title: str, raw: dict) -> str:
    port = raw.get("port", "the exposed port")
    service = raw.get("service", "service")

    if category == "db-exposure":
        return (
            f"Restrict external access to the database service on port `{port}`, "
            "bind it to private interfaces only, and enforce network allowlists or VPN access."
        )
    if category == "remote-access":
        return (
            f"Limit public exposure of the remote access service `{service}` on port `{port}` "
            "and require secure administrative access paths such as VPN, bastion hosts, and MFA."
        )
    if category == "windows-exposure":
        return (
            f"Remove public access to the Windows service on port `{port}` and restrict it to trusted internal networks only."
        )
    if category == "network-exposure":
        return (
            f"Review whether the externally reachable service `{service}` on port `{port}` is required. "
            "If not required, close the port or restrict access with firewall rules."
        )
    return f"Review the externally reachable service reported by `{title}` and restrict unnecessary public access."


def _server_fix_suggestion(category: str, title: str) -> str:
    if category == "sensitive-file":
        return "Remove the sensitive file from public web paths, rotate exposed credentials if any, and verify that backups or config files are not web-accessible."
    if category == "directory-listing":
        return "Disable directory listing on the affected path and ensure direct file browsing is not allowed without explicit intent."
    if category == "admin-exposure":
        return "Restrict the administrative endpoint to trusted networks, add strong authentication, and remove public exposure where possible."
    if category == "default-page":
        return "Replace the default server page with the intended application content and review the deployment for incomplete configuration."
    if category == "information-disclosure":
        return "Suppress unnecessary product and version details from response headers and error pages."
    return f"Review the server exposure reported by `{title}` and remove unnecessary public access or server metadata disclosure."


def _db_fix_suggestion(category: str, title: str) -> str:
    if category == "db-dump":
        return "Remove the database dump or backup file from public web paths, rotate any included credentials, and ensure backup artifacts are stored outside the document root."
    if category == "db-credentials":
        return "Remove database connection strings or credentials from client-accessible content, rotate exposed secrets, and move configuration to secure server-side storage."
    if category == "db-exposure":
        return "Restrict access to the exposed database-related asset and confirm that database services or artifacts are not reachable from the public internet."
    return f"Review the database-related exposure reported by `{title}` and remove public access to the leaked material."


def _dedup_key(finding: Finding) -> str:
    category = str(finding.get("category", "other")).strip().lower()
    location = _normalize_location(str(finding.get("location", "")))

    if category == "headers":
        return f"{category}|{location}|{_header_signature(finding)}"
    if category == "dependency":
        return f"{category}|{_dependency_signature(finding)}"
    if category == "cve":
        return f"{category}|{location}|{_extract_cve_id(finding)}"
    return f"{category}|{location}|{_normalize_text(str(finding.get('title', '')))}"


def _merge_findings(group: list[Finding], dedup_key: str) -> Finding:
    representative = max(group, key=_finding_sort_key)
    merged_sources = list(dict.fromkeys(finding["source"] for finding in group))
    merged_ids = [finding["id"] for finding in group]
    merged_evidence = [text for text in (finding.get("evidence", "").strip() for finding in group) if text]
    merged_description = " ".join(
        text for text in dict.fromkeys(finding.get("description", "").strip() for finding in group) if text
    )
    cvss_values = [finding["cvss_score"] for finding in group if finding.get("cvss_score") is not None]

    raw = dict(representative.get("raw", {}) or {})
    raw["merged_sources"] = merged_sources
    raw["merged_ids"] = merged_ids
    raw["merged_count"] = len(group)
    raw["dedup_key"] = dedup_key

    return Finding(
        id=representative["id"],
        source=representative["source"],
        title=representative["title"],
        severity=representative["severity"],
        cvss_score=max(cvss_values) if cvss_values else representative.get("cvss_score"),
        category=representative["category"],
        location=representative["location"],
        description=merged_description or representative["description"],
        evidence="\n---\n".join(dict.fromkeys(merged_evidence)) if merged_evidence else representative["evidence"],
        raw=raw,
    )


def _finding_sort_key(finding: Finding) -> tuple[int, int, int]:
    source = finding.get("source", "")
    merged_score = 1 if source in {"headers", "zap", "nuclei"} else 0
    return (
        _SEVERITY_ORDER.get(finding.get("severity", "info"), 1),
        1 if finding.get("cvss_score") is not None else 0,
        merged_score,
    )


def _normalize_location(location: str) -> str:
    normalized = location.strip().lower()
    normalized = re.sub(r"/+$", "", normalized)
    return normalized


def _normalize_text(value: str) -> str:
    lowered = value.strip().lower()
    lowered = re.sub(r"\([^)]*\)", "", lowered)
    lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
    return " ".join(lowered.split())


def _network_service_classification(service: dict) -> dict[str, str] | None:
    port = int(service.get("port", 0))

    if port in _CRITICAL_NETWORK_PORTS:
        return {
            "severity": "critical",
            "category": "db-exposure" if port in {6379, 9200, 27017} else "network-exposure",
            "title": "High-risk service exposed to the internet: {service} on port {port}",
            "description": "A high-risk service `{service}` is externally reachable on port `{port}`.",
        }
    if port in {1433, 1521, 3306, 5432}:
        return {
            "severity": "high",
            "category": "db-exposure",
            "title": "Database service exposed to the internet: {service} on port {port}",
            "description": "A database service `{service}` is externally reachable on port `{port}`.",
        }
    if port in {21, 23, 3389, 5900}:
        return {
            "severity": "high",
            "category": "remote-access",
            "title": "Remote access service exposed to the internet: {service} on port {port}",
            "description": "A remote access service `{service}` is externally reachable on port `{port}`.",
        }
    if port in {135, 139, 445}:
        return {
            "severity": "high",
            "category": "windows-exposure",
            "title": "Windows network service exposed to the internet: {service} on port {port}",
            "description": "A Windows network service `{service}` is externally reachable on port `{port}`.",
        }
    return None


def _service_signature(service: dict) -> str:
    port = service.get("port", "")
    protocol = service.get("protocol", "tcp")
    name = service.get("service", "unknown")
    product = service.get("product", "")
    version = service.get("version", "")
    extra = service.get("extrainfo", "")
    parts = [f"{port}/{protocol}", name]
    details = " ".join(part for part in [product, version, extra] if part).strip()
    if details:
        parts.append(details)
    return " ".join(parts)


def _header_signature(finding: Finding) -> str:
    haystack = " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("evidence", "")),
    ]).lower()

    header_name = "header"
    for candidate in _HEADER_NAMES:
        if candidate in haystack:
            header_name = candidate
            break

    issue_type = "weak" if any(token in haystack for token in ("weak", "unsafe", "invalid", "missing samesite", "missing secure", "missing httponly")) else "missing"
    return f"{header_name}|{issue_type}"


def _dependency_signature(finding: Finding) -> str:
    raw = finding.get("raw", {}) or {}
    package = str(raw.get("package", "")).lower()
    vuln_id = str(raw.get("vuln_id", "")).lower()
    aliases = raw.get("aliases", [])
    if isinstance(aliases, list):
        alias_text = ",".join(sorted(str(alias).lower() for alias in aliases))
    else:
        alias_text = str(aliases).lower()
    location = _normalize_location(str(finding.get("location", "")))
    title = _normalize_text(str(finding.get("title", "")))
    return "|".join(part for part in [package, vuln_id or alias_text, location, title] if part)


def _extract_cve_id(finding: Finding) -> str:
    title = str(finding.get("title", ""))
    match = re.search(r"(CVE-\d{4}-\d+)", title, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    raw = finding.get("raw", {}) or {}
    if "cve" in raw:
        return str(raw["cve"]).lower()
    return _normalize_text(title)


def _extract_dependency_cvss(result: dict) -> float | None:
    for key in ("cvss", "cvss_score"):
        value = result.get(key)
        if isinstance(value, (int, float)):
            return float(value)

    for vuln_key in ("vuln_data", "advisory", "via"):
        value = result.get(vuln_key)
        score = _walk_for_cvss(value)
        if score is not None:
            return score
    return None


def _walk_for_cvss(value) -> float | None:
    if isinstance(value, dict):
        for key in ("cvss", "score", "baseScore"):
            score = value.get(key)
            if isinstance(score, (int, float)) and 0 <= float(score) <= 10:
                return float(score)
        for child in value.values():
            score = _walk_for_cvss(child)
            if score is not None:
                return score
    elif isinstance(value, list):
        for item in value:
            score = _walk_for_cvss(item)
            if score is not None:
                return score
    return None


def _severity_from_dependency_result(result: dict, default: Severity) -> Severity:
    cvss = _extract_dependency_cvss(result)
    if cvss is not None:
        return _cvss_to_severity(cvss)

    severity = result.get("severity")
    if severity in _NPM_SEVERITY_MAP:
        return _NPM_SEVERITY_MAP[severity]
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return default


def _build_dependency_description(result: dict) -> str:
    package = result.get("package", "unknown")
    version = result.get("version", "")
    direct = result.get("is_direct")
    fix_versions = result.get("fix_versions", [])
    fix_text = ", ".join(fix_versions) if fix_versions else "no known fix version"
    base = result.get("description", "") or result.get("title", "") or "Dependency vulnerability detected."
    relation = "direct dependency" if direct is True else "transitive dependency" if direct is False else "dependency"
    return f"{base} Affected package: {package} {version}. Scope: {relation}. Fix versions: {fix_text}."
