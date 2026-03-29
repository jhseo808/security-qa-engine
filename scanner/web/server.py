from __future__ import annotations

from urllib.parse import urljoin

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

_SENSITIVE_PATHS: list[tuple[str, str, str, str]] = [
    (".env", "high", "Exposed environment file", "sensitive-file"),
    (".git/config", "high", "Exposed Git metadata", "sensitive-file"),
    ("backup.zip", "high", "Exposed backup archive", "sensitive-file"),
    ("dump.sql", "high", "Exposed database dump", "sensitive-file"),
]

_ADMIN_PATHS: list[str] = [
    "admin",
    "manager/html",
    "actuator",
    "phpinfo.php",
]

_DEFAULT_PAGE_MARKERS: list[tuple[str, str]] = [
    ("welcome to nginx", "Default nginx page exposed"),
    ("apache2 debian default page", "Default Apache page exposed"),
    ("iis windows server", "Default IIS page exposed"),
]


def scan(url: str) -> list[dict]:
    logger.info(f"Server exposure scan: {url}")
    issues: list[dict] = []

    try:
        with httpx.Client(follow_redirects=True, timeout=10, verify=False) as client:
            base_response = client.get(url)
            issues.extend(_check_information_disclosure(base_response))
            issues.extend(_check_default_page(base_response))
            issues.extend(_check_sensitive_paths(client, str(base_response.url)))
            issues.extend(_check_admin_paths(client, str(base_response.url)))
    except httpx.RequestError as error:
        logger.warning(f"Server exposure scan failed: {error}")
        return []

    logger.info(f"Server exposure scan complete: {len(issues)} issues")
    return issues


def _check_information_disclosure(response: httpx.Response) -> list[dict]:
    issues: list[dict] = []
    server = response.headers.get("server", "")
    powered_by = response.headers.get("x-powered-by", "")

    if _looks_like_version_disclosure(server):
        issues.append(_issue(
            "Server version disclosed in response headers",
            "low",
            str(response.url),
            "The Server header exposes product or version details that can help attackers profile the host.",
            f"Server: {server}",
            "information-disclosure",
        ))
    if _looks_like_version_disclosure(powered_by):
        issues.append(_issue(
            "Framework version disclosed in response headers",
            "low",
            str(response.url),
            "The X-Powered-By header exposes framework or runtime details that can help attackers profile the application stack.",
            f"X-Powered-By: {powered_by}",
            "information-disclosure",
        ))

    return issues


def _check_default_page(response: httpx.Response) -> list[dict]:
    body = response.text.lower()
    for marker, title in _DEFAULT_PAGE_MARKERS:
        if marker in body:
            return [_issue(
                title,
                "medium",
                str(response.url),
                "A default web server page is exposed, which can indicate an unreviewed or misconfigured deployment.",
                f"Matched marker: {marker}",
                "default-page",
            )]
    return []


def _check_sensitive_paths(client: httpx.Client, base_url: str) -> list[dict]:
    issues: list[dict] = []
    for path, severity, title, category in _SENSITIVE_PATHS:
        target = urljoin(_normalize_base_url(base_url), path)
        response = _safe_get(client, target)
        if response is None:
            continue
        if response.status_code == 200 and _looks_like_exposed_file(response, path):
            issues.append(_issue(
                title,
                severity,
                str(response.url),
                f"The sensitive path `{path}` is directly accessible over HTTP.",
                f"HTTP {response.status_code}, content-type: {response.headers.get('content-type', '')}",
                category,
            ))
    return issues


def _check_admin_paths(client: httpx.Client, base_url: str) -> list[dict]:
    issues: list[dict] = []
    for path in _ADMIN_PATHS:
        target = urljoin(_normalize_base_url(base_url), path)
        response = _safe_get(client, target)
        if response is None:
            continue

        status = response.status_code
        if status == 200:
            issues.append(_issue(
                f"Administrative path exposed: /{path}",
                "medium",
                str(response.url),
                "An administrative or operational endpoint is directly reachable.",
                f"HTTP {status}",
                "admin-exposure",
            ))
        elif status in {401, 403}:
            issues.append(_issue(
                f"Administrative path externally reachable: /{path}",
                "low",
                str(response.url),
                "An administrative endpoint is externally reachable even though access is restricted.",
                f"HTTP {status}",
                "admin-exposure",
            ))

        if status == 200 and _looks_like_directory_listing(response):
            issues.append(_issue(
                f"Directory listing enabled on /{path}",
                "high",
                str(response.url),
                "Directory listing is enabled and reveals file or folder contents.",
                f"HTTP {status}, page title indicates directory indexing",
                "directory-listing",
            ))
    return issues


def _safe_get(client: httpx.Client, url: str) -> httpx.Response | None:
    try:
        return client.get(url)
    except httpx.RequestError:
        return None


def _normalize_base_url(base_url: str) -> str:
    return base_url if base_url.endswith("/") else f"{base_url}/"


def _looks_like_version_disclosure(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    return "/" in value or any(char.isdigit() for char in value)


def _looks_like_exposed_file(response: httpx.Response, path: str) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    body = response.text[:500].lower()
    lowered_path = path.lower()

    if lowered_path.endswith(".env"):
        return "db_" in body or "secret" in body or "password" in body
    if lowered_path.endswith(".sql"):
        return "create table" in body or "insert into" in body or "mysql dump" in body
    if lowered_path.endswith(".git/config"):
        return "[core]" in body or "[remote" in body
    if lowered_path.endswith(".zip"):
        return "application/zip" in content_type or "application/octet-stream" in content_type
    return response.status_code == 200


def _looks_like_directory_listing(response: httpx.Response) -> bool:
    body = response.text.lower()
    return "index of /" in body or "<title>index of " in body or "directory listing for" in body


def _issue(title: str, severity: str, url: str, description: str, evidence: str, category: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "url": url,
        "description": description,
        "evidence": evidence,
        "category": category,
    }
