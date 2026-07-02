from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    return records


def render_report(findings: list[dict[str, Any]], *, program: str, scope_file: str) -> str:
    counts = Counter(str(item.get("priority", "P3")) for item in findings)
    lines = [
        "# Bug Bounty Recon Report",
        "",
        "## Target",
        "",
        f"- Program: {program}",
        f"- Scope File: {scope_file}",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Summary",
        "",
        f"- Findings: {len(findings)}",
        f"- P0: {counts.get('P0', 0)}",
        f"- P1: {counts.get('P1', 0)}",
        f"- P2: {counts.get('P2', 0)}",
        f"- P3: {counts.get('P3', 0)}",
        "",
        "## Priority Findings",
        "",
    ]
    for index, finding in enumerate(findings, 1):
        verification_status = finding.get("verification_status", "needs_manual_review")
        lines.extend(
            [
                f"### {index}. {finding.get('title', 'Untitled')}",
                "",
                f"- Target: {finding.get('target', '')}",
                f"- Candidate Type: {finding.get('candidate_type', '')}",
                f"- Severity: {finding.get('severity', 'info')}",
                f"- Confidence: {finding.get('confidence', 0)}",
                f"- Verification Status: {verification_status}",
                f"- Auto Exploit: {str(finding.get('auto_exploit', False)).lower()}",
                "- Manual Verification:",
            ]
        )
        steps = finding.get("manual_verification") or []
        for step in steps:
            lines.append(f"  - {step}")
        lines.append("")
    lines.extend(
        [
            "## Out-of-Scope Removed Items",
            "",
            "See harness/state artifacts when present.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--program", default="unknown")
    parser.add_argument("--scope-file", default="unknown")
    args = parser.parse_args()

    report = render_report(
        load_jsonl(args.findings),
        program=args.program,
        scope_file=args.scope_file,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(str(args.output))


if __name__ == "__main__":
    main()
