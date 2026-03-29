from __future__ import annotations

from typing import TypedDict

from scanner.normalizer import FilteredFinding
from utils.logger import get_logger

logger = get_logger(__name__)


class DeltaResult(TypedDict):
    new: list[FilteredFinding]
    persisted: list[FilteredFinding]
    fixed: list[FilteredFinding]


def compare(
    current: list[FilteredFinding],
    baseline: list[FilteredFinding],
) -> DeltaResult:
    """dedup_key 기준으로 current와 baseline finding을 비교해 delta를 반환한다.

    - new: baseline에 없고 current에만 있는 finding
    - persisted: 양쪽 모두 있는 finding
    - fixed: baseline에 있지만 current에 없는 finding
    """
    current_map = _build_key_map(current)
    baseline_map = _build_key_map(baseline)

    current_keys = set(current_map)
    baseline_keys = set(baseline_map)

    new = [current_map[k] for k in current_keys - baseline_keys]
    persisted = [current_map[k] for k in current_keys & baseline_keys]
    fixed = [baseline_map[k] for k in baseline_keys - current_keys]

    logger.info(
        f"Delta: new={len(new)}, persisted={len(persisted)}, fixed={len(fixed)}"
    )
    return DeltaResult(new=new, persisted=persisted, fixed=fixed)


def _build_key_map(findings: list[FilteredFinding]) -> dict[str, FilteredFinding]:
    result: dict[str, FilteredFinding] = {}
    for finding in findings:
        key = _extract_dedup_key(finding)
        if key is None:
            logger.debug(f"dedup_key 없음, 건너뜀: {finding.get('id')} - {finding.get('title')}")
            continue
        if key in result:
            logger.debug(f"dedup_key 중복, 첫 번째 유지: {key}")
            continue
        result[key] = finding
    return result


def _extract_dedup_key(finding: FilteredFinding) -> str | None:
    raw = finding.get("raw") or {}
    return raw.get("dedup_key") or None
