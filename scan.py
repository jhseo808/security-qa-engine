from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from config import load_config, preflight_check
from scanner import normalizer, orchestrator
from utils.ip_validator import validate_url
from utils.logger import get_logger

logger = get_logger(__name__)


def main() -> None:
    args = _parse_args()
    config = load_config()

    if args.url:
        _run_url_scan(args, config)
        return
    if args.path:
        _run_local_scan(args, config)
        return
    if args.war:
        _run_war_scan(args, config)
        return
    if args.from_filtered:
        _run_from_filtered(args)
        return

    logger.error("Specify one target with --url, --path, --war, or --from-filtered.")
    sys.exit(1)


def _run_url_scan(args: argparse.Namespace, config) -> None:
    url = args.url
    try:
        validate_url(url)
    except ValueError as error:
        logger.error(str(error))
        sys.exit(1)

    preflight_check(config, mode="url", include_zap=not args.skip_zap)

    logger.info(f"Starting URL scan: {url}")
    result = asyncio.run(orchestrator.run_url_scanners(
        url=url,
        config=config,
        skip_zap=args.skip_zap,
        full=args.full,
    ))

    expected_scanners = _expected_url_scanners(config, args.skip_zap)
    _save_and_report(
        target=url,
        scan_type="url",
        result=result,
        output_dir=_resolve_output_dir(args.output),
        skip_ai=args.skip_ai,
        config=config,
        expected_scanners=expected_scanners,
        baseline_path=args.baseline,
    )


def _run_war_scan(args: argparse.Namespace, config) -> None:
    from scanner.local import sbom as sbom_scanner
    from scanner import normalizer

    target = Path(args.war).resolve()
    if not target.exists():
        logger.error(f"Path does not exist: {target}")
        sys.exit(1)

    preflight_check(config, mode="war")

    logger.info(f"Starting WAR/SCA scan: {target}")
    result = sbom_scanner.scan(str(target))
    findings = normalizer.normalize_sbom(result)

    _save_and_report(
        target=str(target),
        scan_type="war",
        result=orchestrator.OrchestratorResult(
            findings=findings,
            scanners_run=["grype", "webxml"],
            scanners_failed=[],
        ),
        output_dir=_resolve_output_dir(args.output),
        skip_ai=args.skip_ai,
        config=config,
        expected_scanners=["grype", "webxml"],
        baseline_path=args.baseline,
    )


def _run_local_scan(args: argparse.Namespace, config) -> None:
    path = Path(args.path).resolve()
    if not path.exists():
        logger.error(f"Path does not exist: {path}")
        sys.exit(1)

    preflight_check(config, mode="local")

    logger.info(f"Starting local scan: {path}")
    result = asyncio.run(orchestrator.run_local_scanners(str(path)))

    _save_and_report(
        target=str(path),
        scan_type="local",
        result=result,
        output_dir=_resolve_output_dir(args.output),
        skip_ai=args.skip_ai,
        config=config,
        expected_scanners=["semgrep", "dependency", "secrets"],
        baseline_path=args.baseline,
    )


def _run_from_filtered(args: argparse.Namespace) -> None:
    filtered_file = Path(args.from_filtered)
    if not filtered_file.exists():
        logger.error(f"File does not exist: {filtered_file}")
        sys.exit(1)

    data = json.loads(filtered_file.read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    from engine import prioritizer, qa_converter
    from reports import markdown

    prioritized = prioritizer.prioritize(findings)
    prioritized = _apply_delta(prioritized, getattr(args, "baseline", None))
    test_cases = qa_converter.convert(prioritized)

    output_dir = _resolve_output_dir(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "target": data.get("target", "unknown"),
        "scanned_at": data.get("scanned_at", data.get("filtered_at", "")),
        "scan_type": data.get("scan_type", "unknown"),
        "coverage_status": data.get("coverage_status", "unknown"),
        "report_confidence": data.get("report_confidence", "unknown"),
        "failed_scanners": data.get("failed_scanners", []),
        "ai_status": data.get("ai_status", "unknown"),
        "ai_notes": data.get("ai_notes", ""),
    }
    markdown.generate(test_cases, prioritized, metadata, output_dir)

    logger.info(f"Generated {len(test_cases)} QA test cases.")
    logger.info(f"  {(output_dir / 'test_cases.md')}")
    logger.info(f"  {(output_dir / 'report_dev.md')}")

    config = load_config()
    if not args.skip_jira and config.jira_url and config.jira_user and config.jira_token:
        from integrations.jira import JiraClient

        client = JiraClient(config)
        issue_keys = client.create_issues(test_cases)
        if issue_keys:
            logger.info(f"Created Jira issues: {', '.join(issue_keys)}")
        client.post_delta_comments(prioritized)
    elif not args.skip_jira:
        logger.info("Skipping Jira issue creation because Jira credentials are not configured.")

    _log_completion_summary(
        target=metadata["target"],
        output_dir=output_dir,
        prioritized_findings=prioritized,
        coverage_status=metadata["coverage_status"],
        report_confidence=metadata["report_confidence"],
        failed_scanners=metadata["failed_scanners"],
        ai_status=metadata["ai_status"],
        raw_output=None,
        filtered_output=filtered_file,
        report_output=output_dir / "report_dev.md",
        test_cases_output=output_dir / "test_cases.md",
    )


def _save_and_report(
    target: str,
    scan_type: str,
    result: orchestrator.OrchestratorResult,
    output_dir: Path,
    skip_ai: bool,
    config,
    expected_scanners: list[str],
    baseline_path: str | None = None,
) -> None:
    scan_result = normalizer.build_scan_result(
        target=target,
        scan_type=scan_type,
        findings=result.findings,
        scanners_run=result.scanners_run,
        scanners_failed=result.scanners_failed,
        expected_scanners=expected_scanners,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_output = output_dir / "raw_results.json"
    raw_output.write_text(
        json.dumps(scan_result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    total = len(result.findings)
    by_severity = _count_by_severity(result.findings)
    logger.info(f"Scan complete: {total} findings")
    logger.info(
        "  Critical: %s / High: %s / Medium: %s / Low: %s / Info: %s",
        by_severity["critical"],
        by_severity["high"],
        by_severity["medium"],
        by_severity["low"],
        by_severity["info"],
    )
    logger.info(f"Saved raw results: {raw_output}")

    if scan_result["scanners_failed"]:
        logger.warning(f"Failed scanners: {', '.join(scan_result['scanners_failed'])}")
    if scan_result["coverage_status"] != "complete":
        logger.warning(
            "Coverage is %s and report confidence is %s.",
            scan_result["coverage_status"],
            scan_result["report_confidence"],
        )

    prioritized_findings, ai_status, ai_notes = _build_filtered_findings(
        scan_result=scan_result,
        config=config,
        skip_ai=skip_ai,
    )
    prioritized_findings = _apply_delta(prioritized_findings, baseline_path)
    filtered_result = normalizer.build_filtered_result(
        scan_result=scan_result,
        findings=prioritized_findings,
        ai_status=ai_status,
        ai_notes=ai_notes,
    )

    filtered_output = output_dir / "filtered_results.json"
    filtered_output.write_text(
        json.dumps(filtered_result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info(f"Saved filtered results: {filtered_output}")

    from engine import qa_converter
    from reports import markdown

    test_cases = qa_converter.convert(prioritized_findings)
    metadata = {
        "target": target,
        "scanned_at": scan_result["scanned_at"],
        "scan_type": scan_type,
        "coverage_status": scan_result["coverage_status"],
        "report_confidence": scan_result["report_confidence"],
        "failed_scanners": scan_result["failed_scanners"],
        "ai_status": ai_status,
        "ai_notes": ai_notes,
    }
    markdown.generate(test_cases, prioritized_findings, metadata, output_dir)
    logger.info(f"Generated reports in {output_dir}")

    if ai_status in {"manual_required", "fallback"}:
        logger.info(f"AI notes: {ai_notes}")

    _log_completion_summary(
        target=target,
        output_dir=output_dir,
        prioritized_findings=prioritized_findings,
        coverage_status=scan_result["coverage_status"],
        report_confidence=scan_result["report_confidence"],
        failed_scanners=scan_result["failed_scanners"],
        ai_status=ai_status,
        raw_output=raw_output,
        filtered_output=filtered_output,
        report_output=output_dir / "report_dev.md",
        test_cases_output=output_dir / "test_cases.md",
    )


def _build_filtered_findings(
    scan_result: normalizer.ScanResult,
    config,
    skip_ai: bool,
) -> tuple[list[normalizer.FilteredFinding], normalizer.AIStatus, str]:
    from engine import ai_filter, prioritizer

    findings = scan_result["findings"]

    if skip_ai:
        fallback_findings = normalizer.to_filtered_findings(findings)
        return prioritizer.prioritize(fallback_findings), "skipped", "AI filtering skipped by flag."

    if not config.anthropic_api_key:
        fallback_findings = normalizer.to_filtered_findings(findings)
        note = "ANTHROPIC_API_KEY is not configured. Generated fallback filtered results."
        return prioritizer.prioritize(fallback_findings), "manual_required", note

    try:
        filtered = ai_filter.filter_findings(findings, config)
        return prioritizer.prioritize(filtered), "completed", "AI filtering completed successfully."
    except Exception as error:
        fallback_findings = normalizer.to_filtered_findings(findings)
        note = f"AI filtering failed and fallback prioritization was used: {error}"
        logger.warning(note)
        return prioritizer.prioritize(fallback_findings), "fallback", note


def _expected_url_scanners(config, skip_zap: bool) -> list[str]:
    scanners = ["headers", "db", "server", "network", "ssl_labs"]
    if config.shodan_api_key:
        scanners.append("shodan")
    if not skip_zap:
        scanners.extend(["nuclei", "zap"])
    return scanners


def _resolve_output_dir(base: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(base) / timestamp


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding["severity"]
        if severity in counts:
            counts[severity] += 1
    return counts


def _log_completion_summary(
    target: str,
    output_dir: Path,
    prioritized_findings: list[dict[str, Any]],
    coverage_status: str,
    report_confidence: str,
    failed_scanners: list[str],
    ai_status: str,
    raw_output: Path | None,
    filtered_output: Path,
    report_output: Path,
    test_cases_output: Path,
) -> None:
    action_counts = _count_by_action_status(prioritized_findings)
    summary_lines = [
        "Run summary:",
        f"  Target: {target}",
        f"  Coverage: {coverage_status}",
        f"  Report confidence: {report_confidence}",
        f"  AI status: {ai_status}",
        f"  Failed scanners: {', '.join(failed_scanners) if failed_scanners else 'none'}",
        (
            "  Action queue: "
            f"fix_now={action_counts['fix_now']}, "
            f"review_needed={action_counts['review_needed']}, "
            f"backlog={action_counts['backlog']}"
        ),
        f"  Output directory: {output_dir}",
        f"  Filtered results: {filtered_output}",
        f"  Developer report: {report_output}",
        f"  QA test cases: {test_cases_output}",
    ]
    if raw_output is not None:
        summary_lines.insert(8, f"  Raw results: {raw_output}")

    for line in summary_lines:
        logger.info(line)


def _apply_delta(
    findings: list[normalizer.FilteredFinding],
    baseline_path: str | None,
) -> list[normalizer.FilteredFinding]:
    if not baseline_path:
        return findings

    baseline_file = Path(baseline_path)
    if not baseline_file.exists():
        logger.warning(f"Baseline file not found, skipping delta: {baseline_path}")
        return findings

    from engine.delta import compare

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    baseline_findings = baseline_data.get("findings", [])

    delta = compare(findings, baseline_findings)

    key_to_status: dict[str, str] = {}
    for f in delta["new"]:
        raw_key = (f.get("raw") or {}).get("dedup_key")
        if raw_key:
            key_to_status[raw_key] = "new"
    for f in delta["persisted"]:
        raw_key = (f.get("raw") or {}).get("dedup_key")
        if raw_key:
            key_to_status[raw_key] = "persisted"

    result = []
    for finding in findings:
        raw_key = (finding.get("raw") or {}).get("dedup_key")
        status = key_to_status.get(raw_key) if raw_key else None
        result.append({**finding, "delta_status": status})

    logger.info(
        f"Delta applied — new: {len(delta['new'])}, "
        f"persisted: {len(delta['persisted'])}, "
        f"fixed: {len(delta['fixed'])}"
    )
    return result  # type: ignore[return-value]


def _count_by_action_status(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"fix_now": 0, "review_needed": 0, "backlog": 0}
    for finding in findings:
        if finding.get("false_positive"):
            continue
        action_status = finding.get("action_status", "backlog")
        if action_status in counts:
            counts[action_status] += 1
    return counts


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security QA Engine CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py --url https://target.com --skip-zap
  python scan.py --url https://target.com
  python scan.py --url https://target.com --full
  python scan.py --path ./my-project
        """,
    )

    target = parser.add_mutually_exclusive_group()
    target.add_argument("--url", metavar="URL", help="Target URL")
    target.add_argument("--path", metavar="PATH", help="Local project path")
    target.add_argument("--war", metavar="PATH", help="WAR file or WEB-INF directory for SCA scan")
    target.add_argument("--from-filtered", metavar="FILE", help="Generate reports from filtered_results.json")

    parser.add_argument(
        "--output",
        metavar="DIR",
        default="./output/report",
        help="Root output directory. A timestamped subdirectory is always created.",
    )
    parser.add_argument(
        "--skip-zap",
        action="store_true",
        help="Skip nuclei and ZAP scans.",
    )
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Skip AI filtering and use fallback prioritization only.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run the full ZAP active scan.",
    )
    parser.add_argument(
        "--skip-jira",
        action="store_true",
        help="Skip Jira issue creation in --from-filtered mode.",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Path to a previous filtered_results.json for delta comparison.",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
