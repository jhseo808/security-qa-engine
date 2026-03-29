from __future__ import annotations

import httpx

from scanner.web import server


def test_server_scan_detects_information_disclosure_and_default_page(monkeypatch) -> None:
    def fake_get(self, url, *args, **kwargs):
        if url == "https://example.com":
            return httpx.Response(
                200,
                request=httpx.Request("GET", url),
                headers={"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2"},
                text="<html><title>Welcome to nginx!</title></html>",
            )
        return httpx.Response(404, request=httpx.Request("GET", url), text="not found")

    monkeypatch.setattr(httpx.Client, "get", fake_get)

    issues = server.scan("https://example.com")

    titles = {issue["title"] for issue in issues}
    assert "Server version disclosed in response headers" in titles
    assert "Framework version disclosed in response headers" in titles
    assert "Default nginx page exposed" in titles


def test_server_scan_detects_sensitive_files_and_admin_paths(monkeypatch) -> None:
    responses = {
        "https://example.com": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com"),
            headers={},
            text="ok",
        ),
        "https://example.com/.env": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/.env"),
            headers={"content-type": "text/plain"},
            text="DB_PASSWORD=secret",
        ),
        "https://example.com/.git/config": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/.git/config"),
            text="not found",
        ),
        "https://example.com/backup.zip": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/backup.zip"),
            text="not found",
        ),
        "https://example.com/dump.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/dump.sql"),
            text="not found",
        ),
        "https://example.com/admin": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/admin"),
            headers={"content-type": "text/html"},
            text="<html>admin console</html>",
        ),
        "https://example.com/manager/html": httpx.Response(
            403,
            request=httpx.Request("GET", "https://example.com/manager/html"),
            headers={"content-type": "text/html"},
            text="forbidden",
        ),
        "https://example.com/actuator": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/actuator"),
            text="not found",
        ),
        "https://example.com/phpinfo.php": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/phpinfo.php"),
            text="not found",
        ),
    }

    def fake_get(self, url, *args, **kwargs):
        return responses[url]

    monkeypatch.setattr(httpx.Client, "get", fake_get)

    issues = server.scan("https://example.com")

    titles = {issue["title"] for issue in issues}
    assert "Exposed environment file" in titles
    assert "Administrative path exposed: /admin" in titles
    assert "Administrative path externally reachable: /manager/html" in titles
