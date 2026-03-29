from __future__ import annotations

import json
import subprocess

from utils.logger import get_logger

logger = get_logger(__name__)

_NUCLEI_IMAGE = "projectdiscovery/nuclei"
_TIMEOUT = 300  # seconds


def scan(url: str) -> list[dict]:
    """nuclei Docker 이미지로 CVE 및 취약점 패턴 스캔."""
    logger.info(f"nuclei 스캔 시작: {url}")

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                _NUCLEI_IMAGE,
                "-u", url,
                "-jsonl",
                "-silent",
                "-no-color",
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except FileNotFoundError:
        raise RuntimeError("Docker가 설치되어 있지 않습니다.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nuclei 스캔이 {_TIMEOUT}초 내에 완료되지 않았습니다.")

    if result.returncode not in (0, 1):  # nuclei는 발견 없을 때 1을 반환하기도 함
        raise RuntimeError(f"nuclei 실행 실패:\n{result.stderr}")

    findings = _parse_jsonl(result.stdout)
    logger.info(f"nuclei 스캔 완료: {len(findings)}개 발견")
    return findings


def _parse_jsonl(output: str) -> list[dict]:
    """nuclei JSONL 출력 파싱 (한 줄 = 한 finding)."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings
