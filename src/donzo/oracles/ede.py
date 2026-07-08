from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import oracle_verdict


def evaluate_ede_field_diff(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields: set[str] = set()
    for item in records:
        fields.update(str(field) for field in item.get("sensitive_unneeded_fields") or [])
    if fields:
        return oracle_verdict(
            "confirmed",
            0.82,
            "response includes sensitive fields not justified by UI/API contract",
            "medium",
            evidence=[f"unneeded sensitive field: {field}" for field in sorted(fields)],
        )
    if any(item.get("response_fields") for item in records):
        return oracle_verdict(
            "expected_behavior",
            0.65,
            "response fields were inventoried and no unnecessary sensitive fields were documented",
            "info",
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.35,
        "EDE oracle requires response fields and UI/API contract comparison",
        needs_more_evidence=["response_fields", "ui_needed_fields"],
    )
