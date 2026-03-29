from __future__ import annotations

import json
import os
import subprocess

from utils.logger import get_logger

logger = get_logger(__name__)

_TIMEOUT = 300  # seconds


def scan(path: str) -> dict:
    """semgrep으로 소스코드 정적 분석."""
    logger.info(f"semgrep 스캔 시작: {path}")

    env = {**os.environ, "PYTHONUTF8": "1"}
    try:
        result = subprocess.run(
            [
                "semgrep", "--config", "auto", "--json",
                "--exclude", ".venv",
                "--exclude", "node_modules",
                "--exclude", "__pycache__",
                path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT,
            env=env,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "semgrep이 설치되어 있지 않습니다. `pip install semgrep`으로 설치하세요."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"semgrep 스캔이 {_TIMEOUT}초 내에 완료되지 않았습니다.")

    # semgrep은 발견 없을 때도 returncode=0, 에러 시 1
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"semgrep 출력 파싱 실패: {e}") from e

    count = len(data.get("results", []))
    logger.info(f"semgrep 스캔 완료: {count}개 발견")
    return data
