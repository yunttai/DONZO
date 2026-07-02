from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SEVERITIES = {"info", "low", "medium", "high", "critical"}
SEVERITY_ALIASES = {
    "informational": "info",
    "moderate": "medium",
    "med": "medium",
    "warn": "low",
}


def stable_id(*parts: object) -> str:
    joined = "\x1f".join(str(part or "") for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def normalize_severity(value: object) -> str:
    raw = str(value or "info").strip().lower()
    raw = SEVERITY_ALIASES.get(raw, raw)
    return raw if raw in SEVERITIES else "info"


def normalize_source(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return ["unknown"]


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    title = str(
        record.get("title")
        or record.get("name")
        or record.get("template-id")
        or "Untitled"
    )
    target = str(record.get("target") or record.get("url") or record.get("matched-at") or "")
    candidate_type = str(
        record.get("candidate_type")
        or record.get("type")
        or record.get("matcher-name")
        or "GENERAL_CANDIDATE"
    ).upper()
    severity = normalize_severity(record.get("severity"))
    confidence = record.get("confidence", 0.5)
    try:
        confidence_float = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence_float = 0.5
    source = normalize_source(record.get("source") or record.get("tool"))
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}

    normalized = {
        "finding_id": str(
            record.get("finding_id") or stable_id(title, target, candidate_type, source)
        ),
        "title": title,
        "severity": severity,
        "confidence": confidence_float,
        "target": target,
        "candidate_type": candidate_type,
        "source": source,
        "evidence": evidence,
        "verification_status": str(record.get("verification_status") or "needs_manual_review"),
        "auto_exploit": False,
        "manual_verification": record.get("manual_verification")
        if isinstance(record.get("manual_verification"), list)
        else ["Confirm scope and reproduce manually with safe test accounts or read-only checks."],
    }
    if "risk_score" in record:
        normalized["risk_score"] = record["risk_score"]
    if "priority" in record:
        normalized["priority"] = record["priority"]
    return normalized


def load_records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        data = json.loads(stripped)
        return data if isinstance(data, list) else []
    if stripped.startswith("{"):
        return [json.loads(stripped)]
    records: list[dict[str, Any]] = []
    for line in stripped.splitlines():
        line = line.strip()
        if line:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    text = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()
    records = [normalize_record(record) for record in load_records(text)]
    output = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
