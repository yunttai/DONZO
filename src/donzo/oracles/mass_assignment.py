from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_mass_assignment_read_back(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    persisted: list[str] = []
    for item in records:
        for field in item.get("persisted_unexpected_fields") or []:
            persisted.append(str(field))
        if coerce_bool(item.get("read_back_confirmed")):
            field = str(item.get("field") or item.get("submitted_field") or "unexpected_field")
            persisted.append(field)
    if persisted:
        return oracle_verdict(
            "confirmed",
            0.94,
            "read-back confirmed unexpected server-controlled fields persisted",
            "high",
            evidence=[f"persisted field: {field}" for field in sorted(set(persisted))],
        )
    if any(item.get("read_back_fields") for item in records):
        return oracle_verdict(
            "expected_behavior",
            0.75,
            "read-back did not show unexpected field persistence",
            "info",
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.4,
        "mass assignment requires read-back evidence",
        needs_more_evidence=["read_back_fields"],
    )
