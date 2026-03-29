from __future__ import annotations

import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scanner.local.sbom import (
    _check_error_pages,
    _check_session_config,
    _check_transport_guarantee,
    _find_webxml,
    _parse_grype,
)
from scanner.normalizer import normalize_sbom


# ── grype 파싱 ────────────────────────────────────────────────────────────────

def _grype_match(
    vuln_id: str = "CVE-2023-1234",
    package: str = "log4j",
    version: str = "2.14.1",
    severity: str = "Critical",
    fix_versions: list[str] | None = None,
    cvss_score: float | None = 9.8,
) -> dict:
    return {
        "vulnerability": {
            "id": vuln_id,
            "severity": severity,
            "description": f"{vuln_id} in {package}",
            "fix": {"versions": fix_versions or ["2.17.0"]},
            "urls": [f"https://nvd.nist.gov/vuln/detail/{vuln_id}"],
            "cvss": [{"metrics": {"baseScore": cvss_score}}] if cvss_score else [],
        },
        "artifact": {
            "name": package,
            "version": version,
            "locations": [{"path": f"WEB-INF/lib/{package}-{version}.jar"}],
        },
    }


def test_parse_grype_basic() -> None:
    data = {"matches": [_grype_match()]}
    result = _parse_grype(data)

    assert len(result) == 1
    assert result[0]["vuln_id"] == "CVE-2023-1234"
    assert result[0]["package"] == "log4j"
    assert result[0]["version"] == "2.14.1"
    assert result[0]["severity"] == "critical"
    assert result[0]["cvss_score"] == 9.8


def test_parse_grype_empty_matches() -> None:
    assert _parse_grype({"matches": []}) == []
    assert _parse_grype({}) == []


def test_parse_grype_is_direct_webinf_lib() -> None:
    data = {"matches": [_grype_match()]}
    result = _parse_grype(data)
    assert result[0]["is_direct"] is True


def test_parse_grype_no_cvss() -> None:
    match = _grype_match(cvss_score=None)
    match["vulnerability"]["cvss"] = []
    result = _parse_grype({"matches": [match]})
    assert result[0]["cvss_score"] is None


def test_parse_grype_fix_versions() -> None:
    data = {"matches": [_grype_match(fix_versions=["2.17.0", "2.17.1"])]}
    result = _parse_grype(data)
    assert result[0]["fix_versions"] == ["2.17.0", "2.17.1"]


# ── web.xml 파싱 ──────────────────────────────────────────────────────────────

def _parse_xml(content: str) -> ElementTree.Element:
    return ElementTree.fromstring(content)


def test_transport_guarantee_missing() -> None:
    xml = _parse_xml("""
    <web-app>
        <security-constraint>
            <web-resource-collection><url-pattern>/*</url-pattern></web-resource-collection>
        </security-constraint>
    </web-app>
    """)
    findings = _check_transport_guarantee(xml, "web.xml")
    assert len(findings) == 1
    assert "transport-guarantee" in findings[0]["check"]


def test_transport_guarantee_ok() -> None:
    xml = _parse_xml("""
    <web-app>
        <security-constraint>
            <user-data-constraint>
                <transport-guarantee>CONFIDENTIAL</transport-guarantee>
            </user-data-constraint>
        </security-constraint>
    </web-app>
    """)
    findings = _check_transport_guarantee(xml, "web.xml")
    assert findings == []


def test_session_config_missing() -> None:
    xml = _parse_xml("<web-app></web-app>")
    findings = _check_session_config(xml, "web.xml")
    assert any("session-config" in f["check"] for f in findings)


def test_session_config_httponly_secure_ok() -> None:
    xml = _parse_xml("""
    <web-app>
        <session-config>
            <cookie-config>
                <http-only>true</http-only>
                <secure>true</secure>
            </cookie-config>
        </session-config>
    </web-app>
    """)
    findings = _check_session_config(xml, "web.xml")
    assert findings == []


def test_session_config_httponly_missing() -> None:
    xml = _parse_xml("""
    <web-app>
        <session-config>
            <cookie-config>
                <secure>true</secure>
            </cookie-config>
        </session-config>
    </web-app>
    """)
    findings = _check_session_config(xml, "web.xml")
    assert any("http-only" in f["check"] for f in findings)


def test_error_page_missing() -> None:
    xml = _parse_xml("<web-app></web-app>")
    findings = _check_error_pages(xml, "web.xml")
    assert len(findings) == 1
    assert findings[0]["check"] == "error-page"


def test_error_page_present() -> None:
    xml = _parse_xml("""
    <web-app>
        <error-page><error-code>500</error-code><location>/error.jsp</location></error-page>
    </web-app>
    """)
    findings = _check_error_pages(xml, "web.xml")
    assert findings == []


# ── _find_webxml ──────────────────────────────────────────────────────────────

def test_find_webxml_from_webinf_dir(tmp_path: Path) -> None:
    webinf = tmp_path / "WEB-INF"
    webinf.mkdir()
    webxml = webinf / "web.xml"
    webxml.write_text("<web-app/>")

    result = _find_webxml(tmp_path)
    assert result == webxml


def test_find_webxml_direct(tmp_path: Path) -> None:
    webxml = tmp_path / "web.xml"
    webxml.write_text("<web-app/>")

    result = _find_webxml(tmp_path)
    assert result == webxml


def test_find_webxml_from_war(tmp_path: Path) -> None:
    war_path = tmp_path / "app.war"
    with zipfile.ZipFile(war_path, "w") as zf:
        zf.writestr("WEB-INF/web.xml", "<web-app/>")

    result = _find_webxml(war_path)
    assert result is not None
    assert result.read_text() == "<web-app/>"


def test_find_webxml_not_found(tmp_path: Path) -> None:
    result = _find_webxml(tmp_path)
    assert result is None


# ── normalize_sbom ────────────────────────────────────────────────────────────

def test_normalize_sbom_grype_finding() -> None:
    sbom_result = {
        "findings": [
            {
                "source": "grype",
                "package": "log4j",
                "version": "2.14.1",
                "vuln_id": "CVE-2021-44228",
                "severity": "critical",
                "description": "Log4Shell RCE",
                "fix_versions": ["2.17.0"],
                "cvss_score": 10.0,
                "urls": [],
                "is_direct": True,
                "advisory": {},
            }
        ]
    }
    findings = normalize_sbom(sbom_result)
    assert len(findings) == 1
    assert findings[0]["source"] == "dependency"
    assert "CVE-2021-44228" in findings[0]["title"]
    assert findings[0]["severity"] == "critical"


def test_normalize_sbom_webxml_finding() -> None:
    sbom_result = {
        "findings": [
            {
                "source": "webxml",
                "check": "cookie-secure",
                "severity": "medium",
                "description": "Secure 속성 없음",
                "evidence": "",
                "location": "WEB-INF/web.xml",
            }
        ]
    }
    findings = normalize_sbom(sbom_result)
    assert len(findings) == 1
    assert findings[0]["source"] == "webxml"
    assert findings[0]["category"] == "server"


def test_normalize_sbom_empty() -> None:
    assert normalize_sbom({"findings": []}) == []
