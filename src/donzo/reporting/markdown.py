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
    clusters: list[dict[str, Any]] | None = None,
    summary: dict[str, int] | None = None,
    verification_summary: dict[str, Any] | None = None,
    technology_inferences: list[dict[str, Any]] | None = None,
    api_semantic_map: list[dict[str, Any]] | None = None,
) -> str:
    report_records = [item for item in records if item.get("include_in_final_report") is not False]
    suppressed_count = len(records) - len(report_records)
    counts = Counter(str(item.get("priority", "P3")) for item in report_records)
    cluster_records = clusters or []
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
        f"- Findings/Candidates: {len(report_records)}",
        f"- Suppressed/Retry Candidates: {suppressed_count}",
        f"- Out-of-Scope Removed: {removed_count}",
        f"- P0: {counts.get('P0', 0)}",
        f"- P1: {counts.get('P1', 0)}",
        f"- P2: {counts.get('P2', 0)}",
        f"- P3: {counts.get('P3', 0)}",
        "",
    ]
    if summary:
        insertion = ["## Artifact Summary", ""]
        for key, value in summary.items():
            insertion.append(f"- {key.replace('_', ' ').title()}: {value}")
        insertion.append("")
        lines.extend(insertion)
    if verification_summary:
        lines.extend(["## Verification Summary", ""])
        reviewable_count = verification_summary.get("reviewable_candidates", 0)
        lines.append(f"- Reviewable Candidates: {reviewable_count}")
        lines.append(f"- Filtered Candidates: {verification_summary.get('filtered_candidates', 0)}")
        lines.append(f"- HTTP Probes: {verification_summary.get('probe_count', 0)}")
        lines.append(
            f"- Soft-404 Baselines: {verification_summary.get('soft404_baseline_count', 0)}"
        )
        filter_counts = verification_summary.get("filter_reason_counts") or {}
        if filter_counts:
            lines.extend(["", "### Filter Reasons", ""])
            for reason, count in sorted(filter_counts.items()):
                lines.append(f"- {reason}: {count}")
        unverified_counts = verification_summary.get("unverified_reason_counts") or {}
        if unverified_counts:
            lines.extend(["", "### Unverified Reasons", ""])
            for reason, count in sorted(unverified_counts.items()):
                lines.append(f"- {reason}: {count}")
        lines.append("")
    if technology_inferences:
        lines.extend(["## Technology Inference", ""])
        for item in technology_inferences[:10]:
            technologies = [
                str(tech.get("name") or "")
                for tech in item.get("technologies") or []
                if str(tech.get("name") or "")
            ]
            api_hints = [
                str(hint.get("hint") or "")
                for hint in item.get("api_hints") or []
                if str(hint.get("hint") or "")
            ]
            lines.append(f"### {item.get('origin', '')}")
            lines.append("")
            lines.append(f"- Confidence: {item.get('confidence', 0)}")
            lines.append(f"- Technologies: {', '.join(technologies[:8]) or 'none'}")
            lines.append(f"- API Hints: {', '.join(api_hints[:8]) or 'none'}")
            lines.append(f"- Evidence Items: {len(item.get('evidence') or [])}")
            lines.append("")
    if api_semantic_map:
        lines.extend(["## API Semantic Map", ""])
        for item in api_semantic_map[:12]:
            questions = [
                str(question) for question in item.get("risk_questions") or [] if str(question)
            ]
            object_ids = [str(value) for value in item.get("object_id_params") or [] if str(value)]
            relationships = [
                str(value) for value in item.get("relationship_hints") or [] if str(value)
            ]
            lines.append(f"### {item.get('method', 'GET')} {item.get('url', '')}")
            lines.append("")
            lines.append(f"- Resource: {item.get('resource', 'unknown')}")
            lines.append(f"- Action: {item.get('action', 'unknown')}")
            lines.append(f"- Auth Guess: {item.get('auth_guess', 'unknown')}")
            lines.append(f"- Risk Weight: {item.get('risk_weight', 0)}")
            lines.append(f"- Confidence: {item.get('confidence', 0)}")
            lines.append(f"- Object IDs: {', '.join(object_ids[:8]) or 'none'}")
            lines.append(f"- Relationships: {', '.join(relationships[:8]) or 'none'}")
            lines.append("- Review Questions:")
            for question in questions[:5]:
                lines.append(f"  - {question}")
            lines.append("")
    if cluster_records:
        lines.extend(["## Cluster Summary", ""])
        for index, cluster in enumerate(cluster_records[:10], 1):
            lines.extend(render_cluster(index, cluster))
        lines.extend(["## Manual Verification Queue", ""])
        for cluster in cluster_records[:10]:
            lines.append(
                "- "
                f"{cluster.get('priority', 'P3')} "
                f"{cluster.get('title', 'Candidate Cluster')} "
                f"({cluster.get('count', 0)} item(s))"
            )
        lines.append("")
    lines.extend(["## Priority Findings", ""])
    if not report_records:
        lines.extend(["No reportable findings were generated.", ""])
    for index, record in enumerate(report_records, 1):
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


def render_cluster(index: int, cluster: dict[str, Any]) -> list[str]:
    lines = [
        f"### C{index}. {cluster.get('title', 'Candidate Cluster')}",
        "",
        f"- Type: {cluster.get('cluster_type', '')}",
        f"- Priority: {cluster.get('priority', 'P3')}",
        f"- Risk Score: {cluster.get('risk_score', 0)}",
        f"- Count: {cluster.get('count', 0)}",
        f"- Verified: {cluster.get('verified_count', 0)}",
        f"- Evidence Strength: {cluster.get('evidence_strength', 'weak')}",
        "- Targets:",
    ]
    targets = [str(item) for item in cluster.get("targets") or []]
    for target in targets[:5]:
        lines.append(f"  - {target}")
    if len(targets) > 5:
        lines.append(f"  - ... {len(targets) - 5} more")
    lines.append("")
    return lines


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
