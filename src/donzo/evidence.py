from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from donzo.llm_triage.evidence_pack import redact_value
from donzo.models import stable_id


def write_evidence_notes(
    records: list[dict[str, Any]],
    output_dir: Path,
    *,
    max_chars: int = 4000,
) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    for index, record in enumerate(records, start=1):
        record_id = record_identifier(record, index)
        item_dir = output_dir / safe_path_part(record_id)
        item_dir.mkdir(parents=True, exist_ok=True)
        note_path = item_dir / "notes.md"
        note_path.write_text(
            render_evidence_note(index, record, max_chars=max_chars),
            encoding="utf-8",
        )
        paths.append(str(note_path))
    return paths


def render_evidence_note(index: int, record: dict[str, Any], *, max_chars: int = 4000) -> str:
    redactions: list[str] = []
    redacted_record = redact_value("record", record, redactions, max_chars=max_chars)
    if not isinstance(redacted_record, dict):
        redacted_record = {}
    lines = [
        f"# Evidence Note {index}",
        "",
        "## Candidate",
        "",
        f"- ID: {record_identifier(record, index)}",
        f"- Target: {redacted_record.get('target', redacted_record.get('url', ''))}",
        f"- Type: {redacted_record.get('candidate_type', redacted_record.get('type', ''))}",
        f"- Severity: {redacted_record.get('severity', 'info')}",
        f"- Priority: {redacted_record.get('priority', 'P3')}",
        f"- Confidence: {redacted_record.get('confidence', 0)}",
        (
            "- Verification Status: "
            f"{redacted_record.get('verification_status', 'needs_manual_review')}"
        ),
        f"- Auto Exploit: {str(redacted_record.get('auto_exploit', False)).lower()}",
        "",
        "## Why It Was Queued",
        "",
    ]
    reasons = redacted_record.get("reason") or redacted_record.get("reasons") or []
    if isinstance(reasons, list) and reasons:
        lines.extend(f"- {item}" for item in reasons)
    else:
        lines.append("- No rule reason was supplied.")
    lines.extend(["", "## Manual Verification", ""])
    steps = redacted_record.get("manual_verification") or []
    if isinstance(steps, list) and steps:
        lines.extend(f"- {item}" for item in steps)
    else:
        lines.append("- Confirm scope and reproduce manually with safe read-only checks.")
    lines.extend(["", "## Redacted Record", "", "```json"])
    lines.append(json.dumps(redacted_record, ensure_ascii=False, indent=2, sort_keys=True))
    lines.extend(["```", ""])
    if redactions:
        lines.extend(["## Redactions", ""])
        lines.extend(f"- {item}" for item in sorted(set(redactions)))
        lines.append("")
    return "\n".join(lines)


def record_identifier(record: dict[str, Any], index: int) -> str:
    for key in ("finding_id", "candidate_id", "endpoint_id", "service_id", "asset_id"):
        value = str(record.get(key) or "")
        if value:
            return value
    return stable_id("evidence", index, record.get("target") or record.get("url") or record)


def safe_path_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    return cleaned[:80] or "item"
