from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from utils.logger import get_logger

logger = get_logger(__name__)

_SYFT_IMAGE = "anchore/syft"
_GRYPE_IMAGE = "anchore/grype"
_TIMEOUT = 300


def scan(path: str) -> dict[str, Any]:
    """WAR 파일 또는 WEB-INF 디렉터리를 받아 SCA 점검을 수행한다."""
    target = Path(path).resolve()
    findings: list[dict] = []

    findings.extend(_run_grype(target))
    findings.extend(_check_webxml(target))

    logger.info(f"SBOM/SCA scan complete: {len(findings)} findings")
    return {"target": str(target), "findings": findings}


# ── grype CVE 스캔 ────────────────────────────────────────────────────────────

def _run_grype(target: Path) -> list[dict]:
    logger.info(f"grype 스캔 시작: {target}")
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{target}:/scan:ro",
                _GRYPE_IMAGE,
                "/scan",
                "-o", "json",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Docker is not installed or not available in PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"grype scan timed out: {target}") from error

    if result.returncode not in (0, 1):
        stderr = (result.stderr or "").strip()
        raise RuntimeError(stderr or f"grype exited with code {result.returncode}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.warning("grype 출력 파싱 실패")
        return []

    return _parse_grype(data)


def _parse_grype(data: dict) -> list[dict]:
    findings: list[dict] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cvss_score = _extract_grype_cvss(vuln)
        findings.append({
            "source": "grype",
            "package": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "vuln_id": vuln.get("id", ""),
            "severity": vuln.get("severity", "unknown").lower(),
            "description": vuln.get("description", ""),
            "fix_versions": vuln.get("fix", {}).get("versions", []),
            "cvss_score": cvss_score,
            "urls": vuln.get("urls", []),
            "is_direct": _is_direct(artifact),
            "advisory": vuln,
        })
    logger.info(f"grype: {len(findings)}개 CVE 발견")
    return findings


def _extract_grype_cvss(vuln: dict) -> float | None:
    for cvss in vuln.get("cvss", []):
        score = cvss.get("metrics", {}).get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def _is_direct(artifact: dict) -> bool:
    locations = artifact.get("locations", [])
    for loc in locations:
        path = loc.get("path", "")
        if "WEB-INF/lib" in path:
            return True
    return False


# ── web.xml 보안 설정 점검 ────────────────────────────────────────────────────

def _check_webxml(target: Path) -> list[dict]:
    webxml = _find_webxml(target)
    if not webxml:
        logger.debug("web.xml 없음, 건너뜀")
        return []

    logger.info(f"web.xml 점검: {webxml}")
    try:
        content = webxml.read_text(encoding="utf-8", errors="ignore")
        tree = ElementTree.fromstring(content)
    except Exception as error:
        logger.warning(f"web.xml 파싱 실패: {error}")
        return []

    findings: list[dict] = []
    findings.extend(_check_transport_guarantee(tree, str(webxml)))
    findings.extend(_check_session_config(tree, str(webxml)))
    findings.extend(_check_error_pages(tree, str(webxml)))
    return findings


def _find_webxml(target: Path) -> Path | None:
    # WEB-INF 디렉터리인 경우
    candidate = target / "web.xml"
    if candidate.exists():
        return candidate

    # WEB-INF 하위인 경우
    candidate = target / "WEB-INF" / "web.xml"
    if candidate.exists():
        return candidate

    # WAR 파일인 경우 압축 해제 없이 직접 읽기
    if target.suffix == ".war" and target.is_file():
        try:
            with zipfile.ZipFile(target) as zf:
                names = zf.namelist()
                for name in names:
                    if name.endswith("WEB-INF/web.xml") or name == "web.xml":
                        tmp = target.parent / "_sbom_webxml_tmp.xml"
                        tmp.write_bytes(zf.read(name))
                        return tmp
        except Exception as error:
            logger.warning(f"WAR에서 web.xml 추출 실패: {error}")

    return None


def _check_transport_guarantee(tree: ElementTree.Element, location: str) -> list[dict]:
    """HTTPS 강제 여부 확인 (transport-guarantee)."""
    ns = _detect_ns(tree)
    findings: list[dict] = []
    for sc in tree.findall(f".//{ns}security-constraint"):
        tg = sc.find(f".//{ns}transport-guarantee")
        if tg is None or tg.text != "CONFIDENTIAL":
            findings.append({
                "source": "webxml",
                "check": "transport-guarantee",
                "severity": "medium",
                "description": "web.xml에 HTTPS 강제 설정(transport-guarantee: CONFIDENTIAL)이 없습니다.",
                "evidence": ElementTree.tostring(sc, encoding="unicode")[:300],
                "location": location,
            })
    return findings


def _check_session_config(tree: ElementTree.Element, location: str) -> list[dict]:
    """세션 보안 설정 확인 (HttpOnly, Secure 쿠키)."""
    ns = _detect_ns(tree)
    findings: list[dict] = []
    sc = tree.find(f".//{ns}session-config")
    if sc is None:
        findings.append({
            "source": "webxml",
            "check": "session-config",
            "severity": "medium",
            "description": "web.xml에 session-config가 없습니다. HttpOnly / Secure 쿠키 설정이 누락될 수 있습니다.",
            "evidence": "",
            "location": location,
        })
        return findings

    cp = sc.find(f".//{ns}cookie-config")
    if cp is None:
        findings.append({
            "source": "webxml",
            "check": "cookie-config",
            "severity": "medium",
            "description": "session-config에 cookie-config가 없습니다. HttpOnly / Secure 속성을 명시해야 합니다.",
            "evidence": "",
            "location": location,
        })
        return findings

    http_only = cp.find(f"{ns}http-only")
    secure = cp.find(f"{ns}secure")

    if http_only is None or http_only.text != "true":
        findings.append({
            "source": "webxml",
            "check": "cookie-http-only",
            "severity": "medium",
            "description": "세션 쿠키에 HttpOnly 속성이 설정되지 않았습니다.",
            "evidence": ElementTree.tostring(cp, encoding="unicode")[:300],
            "location": location,
        })
    if secure is None or secure.text != "true":
        findings.append({
            "source": "webxml",
            "check": "cookie-secure",
            "severity": "medium",
            "description": "세션 쿠키에 Secure 속성이 설정되지 않았습니다.",
            "evidence": ElementTree.tostring(cp, encoding="unicode")[:300],
            "location": location,
        })
    return findings


def _check_error_pages(tree: ElementTree.Element, location: str) -> list[dict]:
    """에러 페이지 미설정 확인 (스택 트레이스 노출 위험)."""
    ns = _detect_ns(tree)
    error_pages = tree.findall(f".//{ns}error-page")
    if not error_pages:
        return [{
            "source": "webxml",
            "check": "error-page",
            "severity": "low",
            "description": "web.xml에 error-page가 설정되지 않았습니다. 예외 발생 시 스택 트레이스가 노출될 수 있습니다.",
            "evidence": "",
            "location": location,
        }]
    return []


def _detect_ns(tree: ElementTree.Element) -> str:
    tag = tree.tag
    if tag.startswith("{"):
        return tag[:tag.index("}") + 1]
    return ""
