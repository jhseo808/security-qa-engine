from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

_DB_FILE_PATHS: list[tuple[str, str, str]] = [
    ("db.sql", "Exposed database dump", "db-dump"),
    ("database.sql", "Exposed database dump", "db-dump"),
    ("backup.sql", "Exposed database dump", "db-dump"),
    ("dump.sql", "Exposed database dump", "db-dump"),
    ("db.dump", "Exposed database dump", "db-dump"),
    ("dump.sql.gz", "Exposed compressed database dump", "db-dump"),
]

_CONFIG_SCRIPT_PATHS = [
    "config.js",
    "env.js",
    "settings.js",
]

_CONNECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(postgres(?:ql)?://[^\s\"'<>]+)", re.IGNORECASE),
        "PostgreSQL connection string exposed",
    ),
    (
        re.compile(r"(mysql://[^\s\"'<>]+)", re.IGNORECASE),
        "MySQL connection string exposed",
    ),
    (
        re.compile(r"(mongodb(?:\+srv)?://[^\s\"'<>]+)", re.IGNORECASE),
        "MongoDB connection string exposed",
    ),
    (
        re.compile(r"(redis://[^\s\"'<>]+)", re.IGNORECASE),
        "Redis connection string exposed",
    ),
    (
        re.compile(r"(jdbc:[^\s\"'<>]+)", re.IGNORECASE),
        "JDBC connection string exposed",
    ),
]

_KEYWORD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(db_(?:host|user|username|password|name)\s*[:=]\s*['\"][^'\"]+['\"])",
            re.IGNORECASE,
        ),
        "Database credential material exposed",
    ),
    (
        re.compile(
            r"((?:database|db)(?:Host|User|Password|Name)?\s*[:=]\s*['\"][^'\"]+['\"])",
            re.IGNORECASE,
        ),
        "Database configuration value exposed",
    ),
]


def scan(url: str) -> list[dict]:
    logger.info(f"Database exposure scan: {url}")
    issues: list[dict] = []

    try:
        with httpx.Client(follow_redirects=True, timeout=10, verify=False) as client:
            base_response = client.get(url)
            base_url = str(base_response.url)
            contents: list[tuple[str, str]] = [(base_url, base_response.text)]
            contents.extend(_collect_same_origin_scripts(client, base_url, base_response.text))
            contents.extend(_collect_known_config_scripts(client, base_url))
            issues.extend(_find_connection_leaks(contents))
            issues.extend(_find_exposed_db_files(client, base_url))
    except httpx.RequestError as error:
        logger.warning(f"Database exposure scan failed: {error}")
        return []

    logger.info(f"Database exposure scan complete: {len(issues)} issues")
    return _deduplicate_issues(issues)


def _collect_same_origin_scripts(client: httpx.Client, base_url: str, html: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    base_origin = _origin(base_url)
    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
        target = urljoin(base_url, src)
        if _origin(target) != base_origin:
            continue
        response = _safe_get(client, target)
        if response is None or response.status_code != 200:
            continue
        if "javascript" in response.headers.get("content-type", "").lower() or target.endswith(".js"):
            results.append((str(response.url), response.text))
    return results


def _collect_known_config_scripts(client: httpx.Client, base_url: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for path in _CONFIG_SCRIPT_PATHS:
        target = urljoin(_normalize_base_url(base_url), path)
        response = _safe_get(client, target)
        if response is None or response.status_code != 200:
            continue
        results.append((str(response.url), response.text))
    return results


def _find_connection_leaks(contents: list[tuple[str, str]]) -> list[dict]:
    issues: list[dict] = []
    for location, content in contents:
        snippet = content[:8000]
        for pattern, title in _CONNECTION_PATTERNS:
            match = pattern.search(snippet)
            if match:
                issues.append(_issue(
                    title,
                    "high",
                    location,
                    "A database connection string is exposed in web-accessible content.",
                    _truncate(match.group(1)),
                    "db-credentials",
                ))
        for pattern, title in _KEYWORD_PATTERNS:
            match = pattern.search(snippet)
            if match:
                issues.append(_issue(
                    title,
                    "high",
                    location,
                    "Database-related configuration or credential material is exposed in web-accessible content.",
                    _truncate(match.group(1)),
                    "db-credentials",
                ))
    return issues


def _find_exposed_db_files(client: httpx.Client, base_url: str) -> list[dict]:
    issues: list[dict] = []
    for path, title, category in _DB_FILE_PATHS:
        target = urljoin(_normalize_base_url(base_url), path)
        response = _safe_get(client, target)
        if response is None:
            continue
        if response.status_code == 200 and _looks_like_db_file(response, path):
            issues.append(_issue(
                title,
                "high",
                str(response.url),
                f"The database-related file `{path}` is directly accessible over HTTP.",
                f"HTTP {response.status_code}, content-type: {response.headers.get('content-type', '')}",
                category,
            ))
    return issues


def _looks_like_db_file(response: httpx.Response, path: str) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    body = response.text[:1500].lower()
    lowered_path = path.lower()

    if lowered_path.endswith((".sql", ".dump")):
        return "create table" in body or "insert into" in body or "mysql dump" in body
    if lowered_path.endswith(".gz"):
        return "gzip" in content_type or "application/gzip" in content_type or "octet-stream" in content_type
    return response.status_code == 200


def _deduplicate_issues(issues: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict] = []
    for issue in issues:
        key = (issue["title"], issue["url"], issue["category"])
        if key in seen:
            continue
        seen.add(key)
        result.append(issue)
    return result


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_base_url(base_url: str) -> str:
    return base_url if base_url.endswith("/") else f"{base_url}/"


def _safe_get(client: httpx.Client, url: str) -> httpx.Response | None:
    try:
        return client.get(url)
    except httpx.RequestError:
        return None


def _truncate(value: str, max_length: int = 200) -> str:
    return value if len(value) <= max_length else f"{value[:max_length]}..."


def _issue(title: str, severity: str, url: str, description: str, evidence: str, category: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "url": url,
        "description": description,
        "evidence": evidence,
        "category": category,
    }
