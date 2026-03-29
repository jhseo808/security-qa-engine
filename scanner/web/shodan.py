from __future__ import annotations

import socket
from urllib.parse import urlparse

import requests

from config import Config
from utils.logger import get_logger

logger = get_logger(__name__)

_API_BASE = "https://api.shodan.io"


def scan(url: str, config: Config) -> dict:
    """Shodan API로 노출 포트 및 서비스 정보 조회."""
    if not config.shodan_api_key:
        raise RuntimeError("SHODAN_API_KEY가 설정되지 않았습니다.")

    host = urlparse(url).hostname
    if not host:
        raise ValueError(f"URL에서 호스트를 추출할 수 없습니다: {url}")

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise RuntimeError(f"DNS 해석 실패: {host} — {e}") from e

    logger.info(f"Shodan 조회: {host} ({ip})")

    resp = requests.get(
        f"{_API_BASE}/shodan/host/{ip}",
        params={"key": config.shodan_api_key},
        timeout=30,
    )

    if resp.status_code == 404:
        logger.info(f"Shodan: {ip}에 대한 정보 없음")
        return {}

    resp.raise_for_status()
    data = resp.json()
    logger.info(f"Shodan 조회 완료: {len(data.get('ports', []))}개 포트 노출")
    return data
