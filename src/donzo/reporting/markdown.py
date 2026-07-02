from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any


def render_markdown_report(
    records: list[dict[str, Any]],
    *,
    program: str,
    profile: str,
    scope_file: str,
    removed_count: int = 0,
) -> str:
    counts = Counter(str(item.get("priority", "P3")) for item in records)
    lines = [
        "# Bug Bounty Recon Report",
        "",
        "## Target",
        "",
        f"- Program: {program}",
        f"- Profile: {profile}",
        f"- Scope File: {scope_file}",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Summary",
        "",
        f"- Findings/Candidates: {len(records)}",
        f"- Out-of-Scope Removed: {removed_count}",
        f"- P0: {counts.get('P0', 0)}",
        f"- P1: {counts.get('P1', 0)}",
        f"- P2: {counts.get('P2', 0)}",
        f"- P3: {counts.get('P3', 0)}",
        "",
        "## Priority Findings",
        "",
    ]
    if not records:
        lines.extend(["No reportable findings were generated.", ""])
    for index, record in enumerate(records, 1):
        lines.extend(render_record(index, record))
    lines.extend(
        [
            "## Out-of-Scope Removed Items",
            "",
            "Removed items are written to the companion JSON artifact when present.",
            "",
            "## Appendix",
            "",
            "All items are manual-review candidates. No automatic exploit, secret validation, "
            "or automatic submission was performed.",
            "",
        ]
    )
    return "\n".join(lines)


def render_record(index: int, record: dict[str, Any]) -> list[str]:
    lines = [
        f"### {index}. {record.get('title') or record.get('candidate_type') or 'Candidate'}",
        "",
        f"- Target: {record.get('target', '')}",
        f"- Candidate Type: {record.get('candidate_type', '')}",
        f"- Severity: {record.get('severity', 'info')}",
        f"- Priority: {record.get('priority', 'P3')}",
        f"- Risk Score: {record.get('risk_score', 0)}",
        f"- Confidence: {record.get('confidence', 0)}",
        f"- Verification Status: {record.get('verification_status', 'needs_manual_review')}",
        f"- Auto Exploit: {str(record.get('auto_exploit', False)).lower()}",
        "- Manual Verification:",
    ]
    steps = record.get("manual_verification") or record.get("manual_verification_steps") or []
    for step in steps:
        lines.append(f"  - {step}")
    lines.append("")
    return lines
