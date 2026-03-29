from __future__ import annotations

import re

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

_SENSITIVE_COOKIE_PATTERNS = (
    "session",
    "sess",
    "auth",
    "token",
    "jwt",
    "sid",
    "jsessionid",
    "phpsessid",
)

SECURITY_HEADERS: dict[str, tuple[str, str, str]] = {
    "content-security-policy": (
        "high",
        "Missing CSP header",
        "Content-Security-Policy is missing, which weakens browser-side XSS mitigation.",
    ),
    "strict-transport-security": (
        "high",
        "Missing HSTS header",
        "Strict-Transport-Security is missing, which weakens downgrade protection.",
    ),
    "x-frame-options": (
        "medium",
        "Missing X-Frame-Options header",
        "X-Frame-Options is missing, which can allow clickjacking.",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options header",
        "X-Content-Type-Options: nosniff is missing.",
    ),
    "referrer-policy": (
        "low",
        "Missing Referrer-Policy header",
        "Referrer-Policy is missing, which can leak URL information.",
    ),
    "permissions-policy": (
        "low",
        "Missing Permissions-Policy header",
        "Permissions-Policy is missing, so browser capabilities are not explicitly restricted.",
    ),
}


def scan(url: str) -> list[dict]:
    logger.info(f"Security headers scan: {url}")
    issues: list[dict] = []

    try:
        response = httpx.get(url, follow_redirects=True, timeout=15, verify=False)
    except httpx.RequestError as error:
        logger.warning(f"Header scan request failed: {error}")
        return []

    actual_url = str(response.url)
    response_headers = {key.lower(): value for key, value in response.headers.items()}

    for header_name, (severity, title, description) in SECURITY_HEADERS.items():
        if header_name not in response_headers:
            issues.append({
                "title": title,
                "severity": severity,
                "url": actual_url,
                "description": description,
                "evidence": f"Response header '{header_name}' is missing (HTTP {response.status_code})",
                "header": header_name,
            })
            continue

        value = response_headers[header_name]
        issue = _validate_header_value(header_name, value, actual_url)
        if issue:
            issues.append(issue)

    issues.extend(_validate_cookie_headers(response.headers, actual_url))

    logger.info(f"Security headers scan complete: {len(issues)} issues")
    return issues


def _validate_header_value(header: str, value: str, url: str) -> dict | None:
    normalized = value.lower()

    if header == "strict-transport-security":
        if "max-age=0" in normalized:
            return _issue(
                "HSTS disabled with max-age=0",
                "high",
                url,
                "Strict-Transport-Security disables enforcement when max-age=0 is used.",
                f"Strict-Transport-Security: {value}",
                header,
            )
        if "max-age=" not in normalized:
            return _issue(
                "HSTS missing max-age",
                "high",
                url,
                "Strict-Transport-Security is present but missing a max-age directive.",
                f"Strict-Transport-Security: {value}",
                header,
            )

    if header == "content-security-policy":
        if _csp_directive_contains(normalized, "script-src", ("'unsafe-inline'", "'unsafe-eval'")):
            return _issue(
                "Weak CSP policy allows unsafe script execution",
                "medium",
                url,
                "The script-src directive includes unsafe-inline or unsafe-eval.",
                f"Content-Security-Policy: {value}",
                header,
            )
        if _csp_has_wildcard_source(normalized):
            return _issue(
                "Weak CSP policy uses wildcard sources",
                "medium",
                url,
                "The Content-Security-Policy uses wildcard sources in fetch directives.",
                f"Content-Security-Policy: {value}",
                header,
            )
        if _csp_allows_insecure_objects(normalized):
            return _issue(
                "Weak CSP policy allows plugin content from arbitrary sources",
                "medium",
                url,
                "The object-src directive allows broad plugin content loading.",
                f"Content-Security-Policy: {value}",
                header,
            )
        if _csp_missing_frame_ancestors(normalized):
            return _issue(
                "CSP missing frame-ancestors restriction",
                "low",
                url,
                "The Content-Security-Policy does not define frame-ancestors, so clickjacking protection depends on legacy headers only.",
                f"Content-Security-Policy: {value}",
                header,
            )

    if header == "x-frame-options":
        if normalized not in {"deny", "sameorigin"}:
            return _issue(
                "Weak X-Frame-Options value",
                "medium",
                url,
                "X-Frame-Options should be DENY or SAMEORIGIN.",
                f"X-Frame-Options: {value}",
                header,
            )

    if header == "x-content-type-options" and normalized != "nosniff":
        return _issue(
            "Weak X-Content-Type-Options value",
            "low",
            url,
            "X-Content-Type-Options should be set to nosniff.",
            f"X-Content-Type-Options: {value}",
            header,
        )

    if header == "referrer-policy" and normalized in {"unsafe-url", "origin"}:
        return _issue(
            "Weak Referrer-Policy value",
            "low",
            url,
            "Referrer-Policy exposes more referrer data than recommended.",
            f"Referrer-Policy: {value}",
            header,
        )

    return None


def _validate_cookie_headers(headers, url: str) -> list[dict]:
    issues: list[dict] = []
    set_cookie_headers = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []

    for raw_cookie in set_cookie_headers:
        parsed = _parse_set_cookie(raw_cookie)
        cookie_name = parsed.get("name", "unknown")
        lowered_attrs = {key.lower(): value for key, value in parsed.get("attrs", {}).items()}
        sensitive = _is_sensitive_cookie(cookie_name)
        cookie_severity = "high" if sensitive else "medium"
        cookie_desc_prefix = "Sensitive cookies" if sensitive else "Session cookies"

        if "secure" not in lowered_attrs:
            issues.append(_issue(
                f"Cookie '{cookie_name}' missing Secure attribute",
                cookie_severity,
                url,
                f"{cookie_desc_prefix} should include the Secure attribute.",
                raw_cookie,
                "set-cookie",
            ))
        if "httponly" not in lowered_attrs:
            issues.append(_issue(
                f"Cookie '{cookie_name}' missing HttpOnly attribute",
                cookie_severity,
                url,
                f"{cookie_desc_prefix} should include the HttpOnly attribute.",
                raw_cookie,
                "set-cookie",
            ))
        if "samesite" not in lowered_attrs:
            issues.append(_issue(
                f"Cookie '{cookie_name}' missing SameSite attribute",
                cookie_severity,
                url,
                f"{cookie_desc_prefix} should define SameSite to reduce CSRF risk.",
                raw_cookie,
                "set-cookie",
            ))
        elif lowered_attrs["samesite"].lower() == "none" and "secure" not in lowered_attrs:
            issues.append(_issue(
                f"Cookie '{cookie_name}' uses SameSite=None without Secure",
                "high" if sensitive else "medium",
                url,
                "Cookies with SameSite=None must also include the Secure attribute.",
                raw_cookie,
                "set-cookie",
            ))

    return issues


def _parse_set_cookie(raw_cookie: str) -> dict:
    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    if not parts:
        return {"name": "unknown", "attrs": {}}

    name, _, _ = parts[0].partition("=")
    attrs: dict[str, str] = {}
    for attr in parts[1:]:
        key, sep, value = attr.partition("=")
        attrs[key] = value if sep else ""
    return {"name": name, "attrs": attrs}


def _issue(title: str, severity: str, url: str, description: str, evidence: str, header: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "url": url,
        "description": description,
        "evidence": evidence,
        "header": header,
    }


def _csp_directive_contains(policy: str, directive: str, tokens: tuple[str, ...]) -> bool:
    value = _extract_csp_directive(policy, directive)
    return any(token in value for token in tokens)


def _csp_has_wildcard_source(policy: str) -> bool:
    directives = ("default-src", "script-src", "style-src", "img-src", "connect-src", "frame-src")
    return any("*" in _extract_csp_directive(policy, directive) for directive in directives)


def _csp_allows_insecure_objects(policy: str) -> bool:
    object_src = _extract_csp_directive(policy, "object-src")
    if not object_src:
        return False
    return "'none'" not in object_src and "'self'" not in object_src


def _csp_missing_frame_ancestors(policy: str) -> bool:
    return not _extract_csp_directive(policy, "frame-ancestors")


def _extract_csp_directive(policy: str, directive: str) -> str:
    for segment in policy.split(";"):
        entry = segment.strip()
        if not entry:
            continue
        name, _, value = entry.partition(" ")
        if name == directive:
            return value.strip()
    return ""


def _is_sensitive_cookie(cookie_name: str) -> bool:
    normalized = cookie_name.strip().lower()
    if normalized in _SENSITIVE_COOKIE_PATTERNS:
        return True
    return any(pattern in normalized for pattern in _SENSITIVE_COOKIE_PATTERNS) or bool(
        re.search(r"^(?:__host-|__secure-)", normalized)
    )
