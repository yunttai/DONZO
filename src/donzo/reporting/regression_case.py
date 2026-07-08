from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_regression_cases(
    oracle_results: list[dict[str, Any]],
    *,
    test_plans: list[dict[str, Any]] | None = None,
    security_invariants: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    plan_index = {str(item.get("test_id") or ""): item for item in test_plans or []}
    invariant_index = {
        str(item.get("invariant_id") or ""): item for item in security_invariants or []
    }
    cases: list[dict[str, Any]] = []
    for result in oracle_results:
        verdict = result.get("oracle_verdict") or {}
        if verdict.get("status") != "confirmed":
            continue
        plan = plan_index.get(str(result.get("test_id") or ""), {})
        invariant = invariant_index.get(str(result.get("invariant_id") or ""), {})
        cases.append(regression_case_record(result, plan=plan, invariant=invariant))
    return cases


def regression_case_record(
    oracle_result: dict[str, Any],
    *,
    plan: dict[str, Any],
    invariant: dict[str, Any],
) -> dict[str, Any]:
    oracle_type = str(
        oracle_result.get("oracle_type") or (plan.get("oracle") or {}).get("type") or "manual"
    )
    expected_secure_behavior = expected_behavior_for_oracle(oracle_type)
    return {
        "regression_case_id": stable_id(
            "regression_case",
            oracle_result.get("oracle_result_id"),
            oracle_type,
        ),
        "source_oracle_result_id": oracle_result.get("oracle_result_id"),
        "test_id": oracle_result.get("test_id"),
        "endpoint_id": oracle_result.get("endpoint_id"),
        "invariant_id": oracle_result.get("invariant_id"),
        "oracle_type": oracle_type,
        "candidate_vulnerability": oracle_result.get("candidate_vulnerability")
        or plan.get("candidate_vulnerability"),
        "setup": setup_steps(plan),
        "action": action_steps(plan),
        "expected_secure_behavior": expected_secure_behavior,
        "assertions": assertions_for_oracle(oracle_type),
        "safety_constraints": [
            "run only against local/staging or explicitly authorized test data",
            "do not enumerate real user records",
            "do not validate or expose secrets",
        ],
        "invariant": {
            "type": invariant.get("invariant_type"),
            "description": invariant.get("description"),
        },
    }


def setup_steps(plan: dict[str, Any]) -> list[str]:
    steps = [str(item) for item in plan.get("preconditions") or []]
    return steps or ["Create authorized test accounts and seeded non-sensitive records."]


def action_steps(plan: dict[str, Any]) -> list[str]:
    steps = [str(item) for item in plan.get("manual_steps") or plan.get("steps") or []]
    return steps or ["Repeat the original manual oracle check with test-only inputs."]


def expected_behavior_for_oracle(oracle_type: str) -> str:
    if oracle_type in {"differential_body_oracle", "status_or_body_oracle", "status_oracle"}:
        return "Unauthorized or lower-privileged requests are denied or return only allowed data."
    if oracle_type == "mass_assignment_oracle":
        return (
            "Unexpected write-only or read-only fields are ignored or rejected and do not persist."
        )
    if oracle_type == "field_diff_oracle":
        return "Responses contain only fields required for the caller role and UI workflow."
    if oracle_type in {"state_or_sequence_oracle", "state_change_oracle", "sequence_oracle"}:
        return "Invalid, replayed, or out-of-order transitions do not change protected state."
    if oracle_type == "read_back_oracle":
        return "Protected business values cannot be changed through client-controlled input."
    if oracle_type == "replay_oracle":
        return "Expired, consumed, or context-bound tokens cannot be reused."
    if oracle_type == "validation_oracle":
        return "Disallowed destination, path, template, or sink values are rejected or constrained."
    return "The documented security invariant remains enforced."


def assertions_for_oracle(oracle_type: str) -> list[str]:
    if oracle_type in {"differential_body_oracle", "status_or_body_oracle", "status_oracle"}:
        return ["status is 401/403/404 or body omits protected data"]
    if oracle_type == "mass_assignment_oracle":
        return ["read-back response does not contain unexpected persisted fields"]
    if oracle_type == "field_diff_oracle":
        return ["sensitive unneeded fields are absent from the response"]
    if oracle_type in {"state_or_sequence_oracle", "state_change_oracle", "sequence_oracle"}:
        return ["protected state is unchanged after invalid sequence"]
    if oracle_type == "read_back_oracle":
        return ["server-calculated value is unchanged or recalculated server-side"]
    if oracle_type == "replay_oracle":
        return ["replay attempt is rejected"]
    if oracle_type == "validation_oracle":
        return ["disallowed value is rejected or normalized safely"]
    return ["manual invariant assertion remains true"]
