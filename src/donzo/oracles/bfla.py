from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, is_denied, is_success, oracle_verdict


def evaluate_bfla_role_differential(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or {}
    preconditions_ok = coerce_bool(
        context.get("privileged_actor_can_perform") and context.get("member_must_not_perform")
    ) or any(coerce_bool(item.get("preconditions_satisfied")) for item in records)
    if not preconditions_ok:
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "BFLA oracle requires privileged and lower-privilege role preconditions",
            needs_more_evidence=["role relationship proof"],
        )
    mutation = [
        item
        for item in records
        if str(item.get("probe_role") or "").lower() == "mutation"
        or coerce_bool(item.get("mutated"))
    ]
    if any(
        is_success(item.get("status") or item.get("mutated_status"))
        and (
            coerce_bool(item.get("privileged_action_succeeded"))
            or coerce_bool(item.get("read_back_confirmed"))
            or coerce_bool(item.get("state_changed"))
        )
        for item in mutation
    ):
        return oracle_verdict(
            "confirmed",
            0.92,
            "lower-privilege actor performed privileged action and read-back/body confirmed impact",
            "high",
            evidence=["role preconditions proven", "privileged action succeeded for lower role"],
        )
    if mutation and all(
        is_denied(item.get("status") or item.get("mutated_status")) for item in mutation
    ):
        return oracle_verdict(
            "expected_behavior", 0.84, "lower-privilege action was denied", "info"
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.45,
        "BFLA result needs success plus state/read-back evidence",
        needs_more_evidence=["privileged action result", "state read-back"],
    )
