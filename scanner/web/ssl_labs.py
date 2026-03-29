from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

from utils.logger import get_logger

logger = get_logger(__name__)

_API_BASE = "https://api.ssllabs.com/api/v3"
_POLL_INTERVAL = 15   # seconds
_TIMEOUT = 600        # seconds


def scan(url: str) -> dict:
    """SSL Labs API로 SSL/TLS 등급 및 인증서 분석."""
    host = urlparse(url).hostname
    if not host:
        raise ValueError(f"URL에서 호스트를 추출할 수 없습니다: {url}")

    logger.info(f"SSL Labs 스캔 시작: {host}")

    # 새 분석 시작
    resp = requests.get(
        f"{_API_BASE}/analyze",
        params={"host": host, "startNew": "on", "all": "done"},
        timeout=30,
    )
    resp.raise_for_status()

    # 완료까지 폴링
    deadline = time.time() + _TIMEOUT
    while time.time() < deadline:
        resp = requests.get(
            f"{_API_BASE}/analyze",
            params={"host": host, "all": "done"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "")

        if status == "READY":
            logger.info(f"SSL Labs 스캔 완료: {host}")
            return data
        if status == "ERROR":
            raise RuntimeError(f"SSL Labs 분석 오류: {data.get('statusMessage', '')}")

        logger.debug(f"SSL Labs 상태: {status}")
        time.sleep(_POLL_INTERVAL)

    raise RuntimeError(f"SSL Labs 스캔이 {_TIMEOUT}초 내에 완료되지 않았습니다.")
