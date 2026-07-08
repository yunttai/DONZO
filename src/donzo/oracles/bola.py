from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, is_denied, is_success, oracle_verdict


def evaluate_bola_cross_actor(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = context or {}
    if coerce_bool(context.get("object_public") or context.get("shared_with_comparison_actor")):
        return oracle_verdict(
            "false_positive",
            0.85,
            "object is public or shared with the comparison actor",
            false_positive_reasons=["object access is expected"],
        )
    preconditions_ok = coerce_bool(
        context.get("user_a_owns_object")
        and context.get("user_b_lacks_access")
        and context.get("user_b_can_access_own_object")
    ) or any(coerce_bool(item.get("preconditions_satisfied")) for item in records)
    if not preconditions_ok:
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "BOLA oracle requires A/B ownership and access preconditions",
            needs_more_evidence=["actor relationship proof", "same-type object control"],
        )
    mutation = mutation_records(records)
    if any(
        is_success(item.get("status") or item.get("mutated_status")) for item in mutation
    ) and any(
        coerce_bool(item.get("contains_other_actor_data") or item.get("unauthorized_data_visible"))
        for item in mutation
    ):
        return oracle_verdict(
            "confirmed",
            0.95,
            "comparison actor received another actor's protected object data",
            "high",
            evidence=["A/B preconditions proven", "unauthorized actor got protected data"],
        )
    if any(
        coerce_bool(item.get("state_changed") or item.get("read_back_confirmed"))
        for item in mutation
    ):
        return oracle_verdict(
            "confirmed",
            0.94,
            (
                "comparison actor changed another actor's object and read-back "
                "confirmed the state change"
            ),
            "high",
            evidence=["A/B preconditions proven", "state change read-back confirmed"],
        )
    if mutation and all(
        is_denied(item.get("status") or item.get("mutated_status")) for item in mutation
    ):
        return oracle_verdict(
            "expected_behavior",
            0.86,
            "comparison actor was denied with 401/403/404",
            "info",
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.45,
        "BOLA response is inconclusive without protected data or read-back evidence",
        needs_more_evidence=["body comparison or state read-back"],
    )


def mutation_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in records
        if str(item.get("probe_role") or item.get("role") or "").lower() in {"mutation", "mutated"}
        or coerce_bool(item.get("mutated"))
    ]
