from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from config import Config
from scanner import normalizer
from scanner.web import headers as headers_scanner
from scanner.web import db as db_scanner
from scanner.web import network as network_scanner
from scanner.web import nuclei as nuclei_scanner
from scanner.web import server as server_scanner
from scanner.web import shodan as shodan_scanner
from scanner.web import ssl_labs as ssl_labs_scanner
from scanner.web.zap import ZAPScanner
from scanner.local import semgrep as semgrep_scanner
from scanner.local import dependency as dependency_scanner
from scanner.local import secrets as secrets_scanner
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class OrchestratorResult:
    findings: list[normalizer.Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scanners_failed: list[str] = field(default_factory=list)


async def run_url_scanners(
    url: str,
    config: Config,
    skip_zap: bool = False,
    full: bool = False,
) -> OrchestratorResult:
    """URL 스캐너들을 병렬 실행."""
    tasks: dict[str, asyncio.Task] = {}

    tasks["headers"] = asyncio.create_task(
        asyncio.to_thread(headers_scanner.scan, url)
    )
    tasks["db"] = asyncio.create_task(
        asyncio.to_thread(db_scanner.scan, url)
    )
    tasks["server"] = asyncio.create_task(
        asyncio.to_thread(server_scanner.scan, url)
    )
    tasks["network"] = asyncio.create_task(
        asyncio.to_thread(network_scanner.scan, url)
    )
    tasks["ssl_labs"] = asyncio.create_task(
        asyncio.to_thread(ssl_labs_scanner.scan, url)
    )
    if config.shodan_api_key:
        tasks["shodan"] = asyncio.create_task(
            asyncio.to_thread(shodan_scanner.scan, url, config)
        )
    if not skip_zap:
        tasks["nuclei"] = asyncio.create_task(
            asyncio.to_thread(nuclei_scanner.scan, url)
        )
        tasks["zap"] = asyncio.create_task(
            asyncio.to_thread(ZAPScanner(config).scan, url, full)
        )

    return await _collect(tasks, url_mode=True)


async def run_local_scanners(path: str) -> OrchestratorResult:
    """로컬 스캐너들을 병렬 실행."""
    tasks: dict[str, asyncio.Task] = {
        "semgrep": asyncio.create_task(
            asyncio.to_thread(semgrep_scanner.scan, path)
        ),
        "dependency": asyncio.create_task(
            asyncio.to_thread(dependency_scanner.scan, path)
        ),
        "secrets": asyncio.create_task(
            asyncio.to_thread(secrets_scanner.scan, path)
        ),
    }

    return await _collect(tasks, url_mode=False)


async def _collect(
    tasks: dict[str, asyncio.Task],
    url_mode: bool,
) -> OrchestratorResult:
    """태스크 결과를 수집하고 Finding으로 변환."""
    result = OrchestratorResult()

    raw_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    for name, raw in zip(tasks.keys(), raw_results):
        if isinstance(raw, Exception):
            logger.warning(f"[{name}] 스캔 실패: {raw}")
            result.scanners_failed.append(name)
            continue

        try:
            findings = _normalize(name, raw)
            result.findings.extend(findings)
            result.scanners_run.append(name)
            logger.debug(f"[{name}] {len(findings)}개 finding 정규화 완료")
        except Exception as e:
            logger.warning(f"[{name}] 정규화 실패: {e}")
            result.scanners_failed.append(name)

    return result


def _normalize(name: str, raw) -> list[normalizer.Finding]:
    dispatch = {
        "headers":    lambda r: normalizer.normalize_headers(r),
        "db":         lambda r: normalizer.normalize_db(r),
        "server":     lambda r: normalizer.normalize_server(r),
        "network":    lambda r: normalizer.normalize_network(r),
        "zap":        lambda r: normalizer.normalize_zap(r),
        "nuclei":     lambda r: normalizer.normalize_nuclei(r),
        "ssl_labs":   lambda r: normalizer.normalize_ssl_labs(r),
        "shodan":     lambda r: normalizer.normalize_shodan(r),
        "semgrep":    lambda r: normalizer.normalize_semgrep(r),
        "dependency": lambda r: normalizer.normalize_dependency(r),
        "secrets":    lambda r: normalizer.normalize_secrets(r),
    }
    fn = dispatch.get(name)
    if fn is None:
        raise ValueError(f"알 수 없는 스캐너: {name}")
    return fn(raw)
