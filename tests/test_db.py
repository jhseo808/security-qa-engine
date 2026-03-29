from __future__ import annotations

import httpx

from scanner.web import db


def test_db_scan_detects_connection_string_in_base_page(monkeypatch) -> None:
    responses = {
        "https://example.com": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com"),
            headers={"content-type": "text/html"},
            text="""
            <html>
              <script>
                const DATABASE_URL = "postgres://app:secret@example.com:5432/prod";
              </script>
            </html>
            """,
        ),
        "https://example.com/config.js": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/config.js"),
            text="not found",
        ),
        "https://example.com/env.js": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/env.js"),
            text="not found",
        ),
        "https://example.com/settings.js": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/settings.js"),
            text="not found",
        ),
        "https://example.com/db.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/db.sql"),
            text="not found",
        ),
        "https://example.com/database.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/database.sql"),
            text="not found",
        ),
        "https://example.com/backup.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/backup.sql"),
            text="not found",
        ),
        "https://example.com/dump.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/dump.sql"),
            text="not found",
        ),
        "https://example.com/db.dump": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/db.dump"),
            text="not found",
        ),
        "https://example.com/dump.sql.gz": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/dump.sql.gz"),
            text="not found",
        ),
    }

    def fake_get(self, url, *args, **kwargs):
        return responses[url]

    monkeypatch.setattr(httpx.Client, "get", fake_get)

    issues = db.scan("https://example.com")

    titles = {issue["title"] for issue in issues}
    assert "PostgreSQL connection string exposed" in titles


def test_db_scan_detects_exposed_dump_and_config_script_leak(monkeypatch) -> None:
    responses = {
        "https://example.com": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com"),
            headers={"content-type": "text/html"},
            text='<html><script src="/config.js"></script></html>',
        ),
        "https://example.com/config.js": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/config.js"),
            headers={"content-type": "application/javascript"},
            text='const dbPassword = "secret";',
        ),
        "https://example.com/env.js": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/env.js"),
            text="not found",
        ),
        "https://example.com/settings.js": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/settings.js"),
            text="not found",
        ),
        "https://example.com/db.sql": httpx.Response(
            200,
            request=httpx.Request("GET", "https://example.com/db.sql"),
            headers={"content-type": "text/plain"},
            text="CREATE TABLE users (id int);",
        ),
        "https://example.com/database.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/database.sql"),
            text="not found",
        ),
        "https://example.com/backup.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/backup.sql"),
            text="not found",
        ),
        "https://example.com/dump.sql": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/dump.sql"),
            text="not found",
        ),
        "https://example.com/db.dump": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/db.dump"),
            text="not found",
        ),
        "https://example.com/dump.sql.gz": httpx.Response(
            404,
            request=httpx.Request("GET", "https://example.com/dump.sql.gz"),
            text="not found",
        ),
    }

    def fake_get(self, url, *args, **kwargs):
        return responses[url]

    monkeypatch.setattr(httpx.Client, "get", fake_get)

    issues = db.scan("https://example.com")

    titles = {issue["title"] for issue in issues}
    assert "Exposed database dump" in titles
    assert "Database configuration value exposed" in titles
