from __future__ import annotations

import subprocess
import time
from pathlib import Path

import requests

from config import Config
from utils.logger import get_logger

logger = get_logger(__name__)

_ZAP_READY_TIMEOUT = 120    # seconds
_ZAP_SPIDER_TIMEOUT = 600   # seconds (10분)
_ZAP_ASCAN_TIMEOUT = 3600   # seconds (1시간)
_ZAP_POLL_INTERVAL = 3      # seconds
_SPIDER_POLL_INTERVAL = 5   # seconds
_ASCAN_POLL_INTERVAL = 10   # seconds


class ZAPScanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._base_url = f"http://localhost:{config.zap_port}"
        self._session = requests.Session()
        self._session.headers["X-ZAP-API-Key"] = config.zap_api_key
        self._compose_file = Path(__file__).parent.parent.parent / "docker-compose.yml"

    def scan(self, url: str, full: bool = False) -> list[dict]:
        """ZAP 스캔 실행. Docker 자동 시작/종료.

        full=False: Spider만 (기본, 5-10분)
        full=True:  Spider + Active Scan (30-60분)
        """
        try:
            self.start()
            self.spider_scan(url)
            if full:
                self.active_scan(url)
            return self._get_alerts(url)
        finally:
            self.stop()

    def start(self) -> None:
        """ZAP Docker 컨테이너 시작 후 준비 완료까지 대기."""
        logger.info("ZAP 컨테이너 시작 중...")
        result = subprocess.run(
            [
                "docker", "compose",
                "-f", str(self._compose_file),
                "--profile", "zap",
                "up", "-d",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ZAP 컨테이너 시작 실패:\n{result.stderr}")
        self._wait_for_ready()

    def stop(self) -> None:
        """ZAP Docker 컨테이너 종료."""
        logger.info("ZAP 컨테이너 종료 중...")
        subprocess.run(
            [
                "docker", "compose",
                "-f", str(self._compose_file),
                "--profile", "zap",
                "down",
            ],
            capture_output=True,
        )

    def spider_scan(self, url: str) -> None:
        """Spider 스캔 실행 (완료까지 대기)."""
        logger.info(f"ZAP Spider 스캔 시작: {url}")
        resp = self._api_post("/JSON/spider/action/scan/", {"url": url, "recurse": "true"})
        scan_id = resp.get("scan", "0")

        deadline = time.time() + _ZAP_SPIDER_TIMEOUT
        while time.time() < deadline:
            status_resp = self._api_get("/JSON/spider/view/status/", {"scanId": scan_id})
            progress = int(status_resp.get("status", 0))
            logger.debug(f"Spider 진행률: {progress}%")
            if progress >= 100:
                logger.info("Spider 스캔 완료")
                return
            time.sleep(_SPIDER_POLL_INTERVAL)

        raise RuntimeError(f"ZAP Spider 스캔이 {_ZAP_SPIDER_TIMEOUT}초 내에 완료되지 않았습니다.")

    def active_scan(self, url: str) -> None:
        """Active Scan 실행 (완료까지 대기). Spider 이후에 호출."""
        logger.info(f"ZAP Active Scan 시작: {url}")
        resp = self._api_post("/JSON/ascan/action/scan/", {"url": url, "recurse": "true"})
        scan_id = resp.get("scan", "0")

        deadline = time.time() + _ZAP_ASCAN_TIMEOUT
        while time.time() < deadline:
            status_resp = self._api_get("/JSON/ascan/view/status/", {"scanId": scan_id})
            progress = int(status_resp.get("status", 0))
            logger.debug(f"Active Scan 진행률: {progress}%")
            if progress >= 100:
                logger.info("Active Scan 완료")
                return
            time.sleep(_ASCAN_POLL_INTERVAL)

        raise RuntimeError(f"ZAP Active Scan이 {_ZAP_ASCAN_TIMEOUT}초 내에 완료되지 않았습니다.")

    def _get_alerts(self, url: str) -> list[dict]:
        """스캔된 URL의 alerts 수집."""
        alerts_resp = self._api_get("/JSON/core/view/alerts/", {"baseurl": url})
        alerts: list[dict] = alerts_resp.get("alerts", [])
        logger.info(f"ZAP alerts 수집 완료: {len(alerts)}개")
        return alerts

    def _wait_for_ready(self) -> None:
        deadline = time.time() + _ZAP_READY_TIMEOUT
        while time.time() < deadline:
            try:
                resp = self._session.get(
                    f"{self._base_url}/JSON/core/view/version/",
                    timeout=5,
                )
                if resp.status_code == 200:
                    version = resp.json().get("version", "unknown")
                    logger.info(f"ZAP 준비 완료 (버전: {version})")
                    return
            except requests.RequestException:
                pass
            time.sleep(_ZAP_POLL_INTERVAL)

        raise RuntimeError(
            f"ZAP가 {_ZAP_READY_TIMEOUT}초 내에 준비되지 않았습니다. "
            "`docker logs` 명령으로 ZAP 컨테이너 로그를 확인하세요."
        )

    def _api_get(self, path: str, params: dict | None = None) -> dict:
        resp = self._session.get(
            f"{self._base_url}{path}",
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _api_post(self, path: str, data: dict | None = None) -> dict:
        resp = self._session.post(
            f"{self._base_url}{path}",
            data=data or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
