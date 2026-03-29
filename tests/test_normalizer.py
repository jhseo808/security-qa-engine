from __future__ import annotations

from scanner.normalizer import (
    build_coverage_summary,
    build_filtered_result,
    build_scan_result,
    deduplicate_findings,
    make_finding,
    normalize_dependency,
    normalize_db,
    normalize_headers,
    normalize_network,
    normalize_nuclei,
    normalize_server,
    normalize_secrets,
    normalize_semgrep,
    normalize_shodan,
    normalize_ssl_labs,
    to_filtered_findings,
)


def test_build_coverage_summary_partial() -> None:
    summary = build_coverage_summary(
        expected_scanners=["headers", "ssl_labs", "zap"],
        scanners_run=["headers", "ssl_labs"],
        scanners_failed=["zap"],
    )
    assert summary["coverage_status"] == "partial"
    assert summary["report_confidence"] == "medium"


def test_build_filtered_result_copies_metadata() -> None:
    scan_result = build_scan_result(
        target="https://example.com",
        scan_type="url",
        findings=[],
        scanners_run=["headers"],
        scanners_failed=[],
        expected_scanners=["headers"],
    )
    filtered = build_filtered_result(scan_result, [], "completed", "ok")
    assert filtered["scan_id"] == scan_result["scan_id"]
    assert filtered["ai_status"] == "completed"
    assert filtered["coverage_status"] == "complete"


def test_to_filtered_findings_adds_required_fields() -> None:
    finding = make_finding(
        source="headers",
        title="Missing HSTS",
        severity="high",
        category="headers",
        location="https://example.com",
        description="missing header",
    )
    filtered = to_filtered_findings([finding])[0]
    assert filtered["false_positive"] is False
    assert filtered["priority"] == 5
    assert filtered["action_status"] == "fix_now"
    assert filtered["qa_verifiable"] == "qa_verifiable"
    assert filtered["verification_status"] == "unverified"
    assert "Inspect the response headers" in filtered["reproduction_steps"]
    assert "Strict-Transport-Security" in filtered["fix_suggestion"]


def test_to_filtered_findings_marks_fixable_direct_dependency_as_fix_now() -> None:
    finding = make_finding(
        source="dependency",
        title="PYSEC-001: requests 2.20.0",
        severity="medium",
        category="dependency",
        location="requirements.txt (requests==2.20.0)",
        description="upgrade available",
        raw={
            "package": "requests",
            "vuln_id": "PYSEC-001",
            "fix_versions": ["2.32.4"],
            "is_direct": True,
        },
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["action_status"] == "fix_now"
    assert filtered["qa_verifiable"] == "requires_dev_check"
    assert filtered["verification_status"] == "needs_manual_check"
    assert "Inspect the dependency manifest" in filtered["reproduction_steps"]
    assert "fixed versions" in filtered["fix_suggestion"]


def test_to_filtered_findings_builds_semgrep_reproduction_steps() -> None:
    finding = make_finding(
        source="semgrep",
        title="python.lang.security.audit.exec-detected",
        severity="high",
        category="semgrep",
        location="app/main.py:42",
        description="exec() detected",
        evidence="exec(user_input)",
    )

    filtered = to_filtered_findings([finding])[0]

    assert "Open `app/main.py:42` in the codebase." in filtered["reproduction_steps"]
    assert "exec(user_input)" in filtered["reproduction_steps"]
    assert "safe pattern" in filtered["fix_suggestion"]


def test_to_filtered_findings_builds_shodan_manual_review_steps() -> None:
    finding = make_finding(
        source="shodan",
        title="Exposed ports: 80, 443",
        severity="info",
        category="exposure",
        location="1.2.3.4",
        description="Internet-exposed ports reported by Shodan",
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["qa_verifiable"] == "requires_security_review"
    assert filtered["verification_status"] == "needs_manual_check"
    assert "Escalate to security review" in filtered["reproduction_steps"]
    assert "restrict unnecessary public access" in filtered["fix_suggestion"]


def test_to_filtered_findings_builds_secret_fix_suggestion() -> None:
    finding = make_finding(
        source="secrets",
        title="Secret detected: AWS Access Key",
        severity="high",
        category="secrets",
        location="config.py:5",
        description="AWS key in source",
    )

    filtered = to_filtered_findings([finding])[0]

    assert "rotate the credential immediately" in filtered["fix_suggestion"]


def test_to_filtered_findings_marks_shodan_exposure_as_false_positive() -> None:
    finding = make_finding(
        source="shodan",
        title="Exposed ports: 80, 443",
        severity="info",
        category="exposure",
        location="1.2.3.4",
        description="Internet-exposed ports reported by Shodan",
        evidence="[80, 443]",
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["false_positive"] is True
    assert "fallback rules" in filtered["priority_reason"]


def test_to_filtered_findings_marks_low_signal_optional_header_as_false_positive() -> None:
    finding = make_finding(
        source="headers",
        title="Missing Referrer-Policy header",
        severity="low",
        category="headers",
        location="https://example.com",
        description="Referrer-Policy is missing",
        evidence="",
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["false_positive"] is True
    assert "optional low-signal header observation" in filtered["priority_reason"]


def test_to_filtered_findings_marks_info_dependency_without_fix_as_false_positive() -> None:
    finding = make_finding(
        source="dependency",
        title="PKG-001: sample 1.0",
        severity="info",
        category="dependency",
        location="requirements.txt (sample==1.0)",
        description="informational advisory",
        raw={"package": "sample", "version": "1.0", "is_direct": False},
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["false_positive"] is True
    assert "without remediation path" in filtered["priority_reason"]


def test_semgrep_severity_error_maps_to_high() -> None:
    result = {"results": [{"check_id": "rule1", "path": "a.py", "start": {"line": 10}, "extra": {"severity": "ERROR", "message": "msg", "lines": "", "metadata": {}}}]}
    findings = normalize_semgrep(result)
    assert findings[0]["severity"] == "high"
    assert findings[0]["source"] == "semgrep"


def test_shodan_ports_finding() -> None:
    result = {"ip_str": "1.2.3.4", "hostnames": [], "ports": [80, 443], "vulns": {}}
    findings = normalize_shodan(result)
    assert len(findings) == 1
    assert findings[0]["category"] == "exposure"
    assert findings[0]["severity"] == "info"


def test_shodan_cve_critical() -> None:
    result = {"ip_str": "1.2.3.4", "hostnames": [], "ports": [], "vulns": {"CVE-2021-1234": {"cvss": 9.8, "summary": "Critical vuln"}}}
    findings = normalize_shodan(result)
    cve = next(finding for finding in findings if finding["category"] == "cve")
    assert cve["severity"] == "critical"
    assert cve["cvss_score"] == 9.8


def test_ssl_labs_grade_a_excluded() -> None:
    result = {"host": "example.com", "endpoints": [{"grade": "A", "ipAddress": "1.2.3.4", "details": {}}]}
    assert normalize_ssl_labs(result) == []


def test_ssl_labs_grade_f_is_high() -> None:
    result = {"host": "example.com", "endpoints": [{"grade": "F", "ipAddress": "1.2.3.4", "details": {}}]}
    findings = normalize_ssl_labs(result)
    assert findings[0]["severity"] == "high"


def test_normalize_headers_basic() -> None:
    issues = [{"title": "Missing HSTS", "severity": "high", "url": "https://x.com", "description": "desc", "evidence": ""}]
    findings = normalize_headers(issues)
    assert findings[0]["source"] == "headers"
    assert findings[0]["category"] == "headers"


def test_normalize_server_basic() -> None:
    issues = [{
        "title": "Exposed environment file",
        "severity": "high",
        "url": "https://example.com/.env",
        "description": "The sensitive path is accessible.",
        "evidence": "HTTP 200",
        "category": "sensitive-file",
    }]
    findings = normalize_server(issues)
    assert findings[0]["source"] == "server"
    assert findings[0]["category"] == "sensitive-file"


def test_normalize_db_basic() -> None:
    issues = [{
        "title": "Exposed database dump",
        "severity": "high",
        "url": "https://example.com/db.sql",
        "description": "The dump file is accessible.",
        "evidence": "HTTP 200",
        "category": "db-dump",
    }]
    findings = normalize_db(issues)
    assert findings[0]["source"] == "db"
    assert findings[0]["category"] == "db-dump"


def test_normalize_network_creates_summary_and_db_exposure_findings() -> None:
    result = {
        "host": "example.com",
        "services": [
            {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.25"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.0"},
            {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL", "version": "8.0"},
        ],
    }

    findings = normalize_network(result)

    assert len(findings) == 2
    summary = next(finding for finding in findings if finding["title"] == "Additional externally reachable services detected")
    db_finding = next(finding for finding in findings if finding["category"] == "db-exposure")
    assert summary["severity"] == "high"
    assert "22/tcp ssh OpenSSH 9.0" in summary["evidence"]
    assert db_finding["severity"] == "high"
    assert db_finding["location"] == "example.com:3306/tcp"


def test_to_filtered_findings_builds_network_reproduction_steps_and_fix_suggestion() -> None:
    finding = make_finding(
        source="network",
        title="Database service exposed to the internet: mysql on port 3306",
        severity="high",
        category="db-exposure",
        location="example.com:3306/tcp",
        description="A database service is externally reachable.",
        evidence="3306/tcp mysql MySQL 8.0",
        raw={"port": 3306, "service": "mysql"},
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["qa_verifiable"] == "qa_verifiable"
    assert filtered["evidence_quality"] == "strong"
    assert "Re-run a targeted port scan" in filtered["reproduction_steps"]
    assert "Restrict external access to the database service" in filtered["fix_suggestion"]


def test_to_filtered_findings_builds_server_reproduction_steps_and_fix_suggestion() -> None:
    finding = make_finding(
        source="server",
        title="Exposed environment file",
        severity="high",
        category="sensitive-file",
        location="https://example.com/.env",
        description="The .env file is web-accessible.",
        evidence="HTTP 200, content-type: text/plain",
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["qa_verifiable"] == "qa_verifiable"
    assert filtered["evidence_quality"] == "strong"
    assert "Confirm the HTTP status code and response body" in filtered["reproduction_steps"]
    assert "Remove the sensitive file from public web paths" in filtered["fix_suggestion"]


def test_to_filtered_findings_builds_db_reproduction_steps_and_fix_suggestion() -> None:
    finding = make_finding(
        source="db",
        title="PostgreSQL connection string exposed",
        severity="high",
        category="db-credentials",
        location="https://example.com/config.js",
        description="A database connection string is exposed in JavaScript.",
        evidence="postgres://user:pass@example.com:5432/app",
    )

    filtered = to_filtered_findings([finding])[0]

    assert filtered["qa_verifiable"] == "qa_verifiable"
    assert filtered["evidence_quality"] == "strong"
    assert "Verify the reported database-related exposure" in filtered["reproduction_steps"]
    assert "Remove database connection strings or credentials" in filtered["fix_suggestion"]


def test_normalize_nuclei_severity_mapping() -> None:
    results = [{"template-id": "cves/CVE-2021-1", "info": {"name": "Test CVE", "severity": "critical", "description": ""}, "matched-at": "https://x.com"}]
    findings = normalize_nuclei(results)
    assert findings[0]["severity"] == "critical"
    assert findings[0]["category"] == "cves"


def test_normalize_dependency_pip_audit() -> None:
    results = [{
        "source": "pip-audit",
        "package": "requests",
        "version": "2.0",
        "vuln_id": "PYSEC-001",
        "description": "vuln",
        "fix_versions": ["2.1"],
        "aliases": ["CVE-2024-0001"],
        "cvss_score": 9.1,
        "is_direct": True,
    }]
    findings = normalize_dependency(results)
    assert findings[0]["source"] == "dependency"
    assert "PYSEC-001" in findings[0]["title"]
    assert findings[0]["severity"] == "critical"
    assert findings[0]["cvss_score"] == 9.1


def test_normalize_dependency_npm_audit() -> None:
    results = [{
        "source": "npm-audit",
        "package": "lodash",
        "severity": "high",
        "description": "Prototype pollution",
        "via": ["lodash"],
        "fix_available": True,
        "is_direct": False,
        "cvss_score": 7.4,
    }]
    findings = normalize_dependency(results)
    assert findings[0]["severity"] == "high"
    assert findings[0]["cvss_score"] == 7.4
    assert "fix available: True" in findings[0]["evidence"]


def test_normalize_secrets() -> None:
    result = {"results": {"config.py": [{"type": "AWS Access Key", "line_number": 5, "hashed_secret": "abc123"}]}}
    findings = normalize_secrets(result)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "AWS Access Key" in findings[0]["title"]


def test_deduplicate_findings_merges_header_duplicates() -> None:
    findings = [
        make_finding(
            source="headers",
            title="Missing Strict-Transport-Security",
            severity="high",
            category="headers",
            location="https://example.com/",
            description="HSTS header is missing.",
            evidence="header absent",
        ),
        make_finding(
            source="nuclei",
            title="Missing Strict-Transport-Security header",
            severity="medium",
            category="headers",
            location="https://example.com",
            description="Strict-Transport-Security not configured.",
            evidence="nuclei match",
        ),
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 1
    assert deduped[0]["severity"] == "high"
    assert deduped[0]["raw"]["merged_count"] == 2
    assert deduped[0]["raw"]["merged_sources"] == ["headers", "nuclei"]
    assert "nuclei match" in deduped[0]["evidence"]


def test_build_scan_result_deduplicates_findings() -> None:
    findings = [
        make_finding(
            source="dependency",
            title="PYSEC-001: requests 2.0",
            severity="critical",
            category="dependency",
            location="requirements.txt (requests==2.0)",
            description="requests vulnerable",
            raw={"package": "requests", "vuln_id": "PYSEC-001", "aliases": ["CVE-2024-0001"]},
        ),
        make_finding(
            source="dependency",
            title="PYSEC-001: requests 2.0",
            severity="high",
            category="dependency",
            location="requirements.txt (requests==2.0)",
            description="requests vulnerable duplicate",
            raw={"package": "requests", "vuln_id": "PYSEC-001", "aliases": ["CVE-2024-0001"]},
        ),
    ]

    scan_result = build_scan_result(
        target="repo",
        scan_type="local",
        findings=findings,
        scanners_run=["dependency"],
        scanners_failed=[],
        expected_scanners=["dependency"],
    )

    assert len(scan_result["findings"]) == 1
    assert scan_result["findings"][0]["raw"]["merged_count"] == 2
