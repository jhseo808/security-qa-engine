from __future__ import annotations

from scanner.web.headers import _validate_cookie_headers, _validate_header_value


class _Headers:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def get_list(self, key: str) -> list[str]:
        if key.lower() == "set-cookie":
            return self._values
        return []


def test_validate_hsts_disabled() -> None:
    issue = _validate_header_value("strict-transport-security", "max-age=0", "https://example.com")
    assert issue is not None
    assert issue["severity"] == "high"


def test_validate_csp_unsafe_inline() -> None:
    issue = _validate_header_value("content-security-policy", "default-src 'self'; script-src 'unsafe-inline'", "https://example.com")
    assert issue is not None
    assert "unsafe-inline" in issue["description"]


def test_validate_csp_wildcard_in_fetch_directive() -> None:
    issue = _validate_header_value(
        "content-security-policy",
        "default-src 'self'; connect-src *",
        "https://example.com",
    )
    assert issue is not None
    assert "wildcard" in issue["description"].lower()


def test_validate_csp_missing_frame_ancestors() -> None:
    issue = _validate_header_value(
        "content-security-policy",
        "default-src 'self'; script-src 'self'",
        "https://example.com",
    )
    assert issue is not None
    assert "frame-ancestors" in issue["title"]


def test_validate_x_frame_options_invalid() -> None:
    issue = _validate_header_value("x-frame-options", "ALLOWALL", "https://example.com")
    assert issue is not None
    assert issue["severity"] == "medium"


def test_validate_cookie_headers_missing_flags() -> None:
    headers = _Headers(["sessionid=abc123; Path=/"])
    issues = _validate_cookie_headers(headers, "https://example.com")
    titles = [issue["title"] for issue in issues]
    assert any("Secure" in title for title in titles)
    assert any("HttpOnly" in title for title in titles)
    assert any("SameSite" in title for title in titles)


def test_validate_cookie_headers_no_issue_when_flags_present() -> None:
    headers = _Headers(["sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"])
    issues = _validate_cookie_headers(headers, "https://example.com")
    assert issues == []


def test_validate_cookie_headers_samesite_none_requires_secure() -> None:
    headers = _Headers(["sessionid=abc123; Path=/; HttpOnly; SameSite=None"])
    issues = _validate_cookie_headers(headers, "https://example.com")
    titles = [issue["title"] for issue in issues]
    assert any("SameSite=None without Secure" in title for title in titles)


def test_validate_sensitive_cookie_missing_flags_is_high_severity() -> None:
    headers = _Headers(["__Host-session=abc123; Path=/"])
    issues = _validate_cookie_headers(headers, "https://example.com")
    assert issues
    assert all(issue["severity"] == "high" for issue in issues)
