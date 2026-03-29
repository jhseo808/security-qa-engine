from __future__ import annotations

import json

from config import Config
from scanner.normalizer import FilteredFinding, Finding


def filter_findings(findings: list[Finding], config: Config) -> list[FilteredFinding]:
    if not config.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not configured. Use --skip-ai or provide the key in .env."
        )

    try:
        import anthropic
    except ImportError as error:
        raise RuntimeError(
            "anthropic package is not installed. Install it with `pip install anthropic`."
        ) from error

    client = anthropic.Anthropic(api_key=config.anthropic_api_key)
    prompt = _build_prompt(findings)
    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_response(message.content[0].text)


def _build_prompt(findings: list[Finding]) -> str:
    findings_json = json.dumps(findings, ensure_ascii=False, indent=2)
    return f"""Analyze the following security scan findings and return only a JSON array in filtered_results.json item format.

Tasks:
1. Remove false positives by marking them with false_positive=true.
2. Assign priority from 1 to 5 for actionable findings.
3. Add reproduction_steps and fix_suggestion for each actionable finding.
4. Add action_status using one of: fix_now, review_needed, backlog.
5. Add qa_verifiable using one of: qa_verifiable, requires_dev_check, requires_security_review.
6. Add verification_status using one of: unverified, reproduced, needs_manual_check, fixed_pending_retest.
7. Add evidence_quality using one of: strong, medium, weak, manual_check_required.

Findings:
{findings_json}

Return each item with all original finding fields plus:
- priority: int (1-5)
- false_positive: bool
- action_status: "fix_now" | "review_needed" | "backlog"
- qa_verifiable: "qa_verifiable" | "requires_dev_check" | "requires_security_review"
- verification_status: "unverified" | "reproduced" | "needs_manual_check" | "fixed_pending_retest"
- evidence_quality: "strong" | "medium" | "weak" | "manual_check_required"
- reproduction_steps: str
- fix_suggestion: str
- priority_reason: str
"""


def _parse_response(text: str) -> list[FilteredFinding]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])
    return json.loads(text)
