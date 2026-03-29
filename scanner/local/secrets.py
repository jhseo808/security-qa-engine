from __future__ import annotations

import json
import subprocess

from utils.logger import get_logger

logger = get_logger(__name__)

_TIMEOUT = 60  # seconds


def scan(path: str) -> dict:
    """detect-secrets로 소스코드 내 시크릿(API 키, 비밀번호 등) 탐지."""
    logger.info(f"시크릿 스캔 시작: {path}")

    try:
        result = subprocess.run(
            ["detect-secrets", "scan", path],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "detect-secrets가 설치되어 있지 않습니다. `pip install detect-secrets`으로 설치하세요."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"시크릿 스캔이 {_TIMEOUT}초 내에 완료되지 않았습니다.")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"detect-secrets 출력 파싱 실패: {e}") from e

    total = sum(len(v) for v in data.get("results", {}).values())
    logger.info(f"시크릿 스캔 완료: {total}개 의심 항목 발견")
    return data
