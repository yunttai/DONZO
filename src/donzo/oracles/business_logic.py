from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_business_logic_sequence_state(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if any(
        coerce_bool(item.get("invalid_transition_succeeded"))
        or coerce_bool(item.get("forbidden_state_transition"))
        or coerce_bool(item.get("state_changed"))
        for item in records
    ):
        if any(coerce_bool(item.get("read_back_confirmed")) for item in records):
            return oracle_verdict(
                "confirmed",
                0.9,
                (
                    "forbidden business sequence changed protected state and "
                    "read-back confirmed impact"
                ),
                "high",
                evidence=["invalid sequence accepted", "state read-back confirmed"],
            )
        return oracle_verdict(
            "probable",
            0.62,
            "forbidden sequence appeared to succeed but read-back is missing",
            "medium",
            needs_more_evidence=["state read-back"],
        )
    if any(item.get("after_state") and item.get("expected_state") for item in records):
        return oracle_verdict(
            "expected_behavior",
            0.72,
            "state remained consistent with expected secure workflow",
            "info",
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.38,
        "business logic oracle needs before/after state and sequence evidence",
        needs_more_evidence=["before_state", "after_state", "expected_state"],
    )
