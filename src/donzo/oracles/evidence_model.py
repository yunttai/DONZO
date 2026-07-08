from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_evidence_index(oracle_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for result in oracle_results:
        for path in result.get("evidence_files") or []:
            records.append(
                {
                    "evidence_id": stable_id(
                        "oracle_evidence", result.get("oracle_result_id"), path
                    ),
                    "oracle_result_id": result.get("oracle_result_id"),
                    "test_id": result.get("test_id"),
                    "endpoint_id": result.get("endpoint_id"),
                    "path": str(path),
                    "redaction_required": True,
                    "source": "manual_oracle_result",
                }
            )
    return dedupe_by_id(records, "evidence_id")


def dedupe_by_id(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        value = str(record.get(key) or "")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(record)
    return output
