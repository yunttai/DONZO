from __future__ import annotations

from typing import Any

from donzo.oracles.oracle_models import (
    coerce_bool,
    is_denied_status,
    is_success_status,
    oracle_result_record,
)


def evaluate_oracle_results(
    test_plans: list[dict[str, Any]],
    oracle_templates: list[dict[str, Any]],
    manual_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    plan_index = {str(item.get("test_id") or ""): item for item in test_plans}
    template_index = {str(item.get("test_id") or ""): item for item in oracle_templates}
    results: list[dict[str, Any]] = []
    for manual_result in manual_results:
        test_id = str(manual_result.get("test_id") or "")
        plan = plan_index.get(test_id, {})
        template = template_index.get(test_id, {})
        verdict = evaluate_oracle_result(plan, template, manual_result)
        results.append(
            oracle_result_record(
                test_plan=plan,
                oracle_template=template,
                manual_result=manual_result,
                verdict=verdict,
            )
        )
    return results


def evaluate_oracle_result(
    test_plan: dict[str, Any],
    oracle_template: dict[str, Any],
    manual_result: dict[str, Any],
) -> dict[str, Any]:
    override = forced_status(manual_result)
    if override:
        return override
    missing = missing_required_evidence(oracle_template, manual_result)
    if missing:
        return {
            "status": "needs_more_evidence",
            "confidence": 0.3,
            "reason": "manual result is missing required oracle fields or evidence",
            "severity_hint": "info",
            "needs_more_evidence": missing,
        }
    oracle_type = str(
        oracle_template.get("oracle_type")
        or (test_plan.get("oracle") or {}).get("type")
        or manual_result.get("oracle_type")
        or "manual_evidence_oracle"
    )
    if oracle_type in {"differential_body_oracle", "body_oracle"}:
        return evaluate_differential_body(manual_result)
    if oracle_type in {"status_or_body_oracle", "status_oracle"}:
        return evaluate_status_or_body(manual_result)
    if oracle_type == "mass_assignment_oracle":
        return evaluate_mass_assignment(manual_result)
    if oracle_type == "field_diff_oracle":
        return evaluate_field_diff(manual_result)
    if oracle_type in {"state_or_sequence_oracle", "state_change_oracle", "sequence_oracle"}:
        return evaluate_state_or_sequence(manual_result)
    if oracle_type in {"read_back_oracle"}:
        return evaluate_read_back(manual_result)
    if oracle_type in {"replay_oracle"}:
        return evaluate_replay(manual_result)
    if oracle_type in {"validation_oracle"}:
        return evaluate_validation(manual_result)
    return evaluate_manual(manual_result)


def forced_status(manual_result: dict[str, Any]) -> dict[str, Any] | None:
    if coerce_bool(manual_result.get("out_of_scope")):
        return verdict(
            "out_of_scope", 0.95, "manual result marked the target or evidence out of scope", "info"
        )
    if coerce_bool(manual_result.get("duplicate")):
        return verdict("duplicate_candidate", 0.9, "manual result marked this as duplicate", "info")
    if coerce_bool(manual_result.get("false_positive")):
        return verdict(
            "false_positive", 0.85, "manual result marked this as false positive", "info"
        )
    explicit = str(manual_result.get("status") or "").strip()
    if explicit in {
        "confirmed",
        "not_reproducible",
        "needs_more_evidence",
        "expected_behavior",
        "false_positive",
        "out_of_scope",
        "duplicate_candidate",
    }:
        return verdict(explicit, 0.75, "manual result supplied an explicit accepted status", "info")
    return None


def missing_required_evidence(
    oracle_template: dict[str, Any],
    manual_result: dict[str, Any],
) -> list[str]:
    required = [str(item) for item in oracle_template.get("required_manual_fields") or []]
    missing = [
        item
        for item in required
        if item != "notes" and manual_result.get(item) in (None, "", [], {})
    ]
    if not manual_result.get("evidence_files"):
        missing.append("evidence_files")
    return sorted(set(missing))


def evaluate_differential_body(manual_result: dict[str, Any]) -> dict[str, Any]:
    if is_success_status(manual_result.get("mutated_status")) and coerce_bool(
        manual_result.get("response_contains_other_user_data")
        or manual_result.get("unauthorized_data_visible")
    ):
        return verdict(
            "confirmed",
            0.95,
            "unauthorized actor received successful response containing protected data",
            "high",
        )
    if is_denied_status(manual_result.get("mutated_status")):
        return verdict(
            "expected_behavior", 0.85, "mutated request was denied with 401/403/404", "info"
        )
    return verdict(
        "needs_more_evidence",
        0.45,
        "differential body evidence is inconclusive",
        "info",
        ["body comparison"],
    )


def evaluate_status_or_body(manual_result: dict[str, Any]) -> dict[str, Any]:
    if is_success_status(manual_result.get("mutated_status")) and (
        coerce_bool(manual_result.get("privileged_action_succeeded"))
        or coerce_bool(manual_result.get("unauthorized_data_visible"))
    ):
        return verdict(
            "confirmed", 0.9, "lower-privileged actor succeeded or saw privileged data", "high"
        )
    if is_denied_status(manual_result.get("mutated_status")):
        return verdict("expected_behavior", 0.82, "privileged action was denied", "info")
    return verdict(
        "needs_more_evidence",
        0.45,
        "status/body evidence is inconclusive",
        "info",
        ["authorization comparison"],
    )


def evaluate_mass_assignment(manual_result: dict[str, Any]) -> dict[str, Any]:
    persisted = manual_result.get("persisted_unexpected_fields") or []
    if persisted or coerce_bool(manual_result.get("read_back_confirmed")):
        return verdict(
            "confirmed", 0.94, "read-back confirmed unexpected field persistence", "high"
        )
    if manual_result.get("read_back_fields") and not persisted:
        return verdict(
            "not_reproducible", 0.82, "read-back did not show unexpected field persistence", "info"
        )
    return verdict(
        "needs_more_evidence",
        0.4,
        "mass assignment check requires read-back evidence",
        "info",
        ["read_back_fields"],
    )


def evaluate_field_diff(manual_result: dict[str, Any]) -> dict[str, Any]:
    fields = manual_result.get("sensitive_unneeded_fields") or []
    if fields:
        return verdict(
            "confirmed",
            0.82,
            "response includes sensitive fields not justified by UI/caller role",
            "medium",
        )
    if manual_result.get("response_fields"):
        return verdict(
            "expected_behavior", 0.65, "no unnecessary sensitive fields were documented", "info"
        )
    return verdict(
        "needs_more_evidence",
        0.35,
        "field diff evidence is missing",
        "info",
        ["response_fields", "ui_needed_fields"],
    )


def evaluate_state_or_sequence(manual_result: dict[str, Any]) -> dict[str, Any]:
    if coerce_bool(manual_result.get("invalid_transition_succeeded")) or coerce_bool(
        manual_result.get("state_changed")
    ):
        return verdict(
            "confirmed",
            0.9,
            "invalid/replayed/out-of-order transition changed protected state",
            "high",
        )
    if manual_result.get("after_state") and manual_result.get("expected_state"):
        return verdict(
            "not_reproducible",
            0.78,
            "state remained consistent with the expected secure workflow",
            "info",
        )
    return verdict(
        "needs_more_evidence",
        0.4,
        "state transition evidence is incomplete",
        "info",
        ["before_state", "after_state"],
    )


def evaluate_read_back(manual_result: dict[str, Any]) -> dict[str, Any]:
    if coerce_bool(manual_result.get("protected_value_changed")):
        return verdict(
            "confirmed", 0.9, "read-back showed protected value changed unexpectedly", "high"
        )
    if manual_result.get("read_back_fields"):
        return verdict(
            "not_reproducible", 0.75, "read-back did not show protected value changes", "info"
        )
    return verdict(
        "needs_more_evidence", 0.4, "read-back fields are required", "info", ["read_back_fields"]
    )


def evaluate_replay(manual_result: dict[str, Any]) -> dict[str, Any]:
    if coerce_bool(manual_result.get("replay_succeeded")):
        return verdict(
            "confirmed", 0.88, "expired/used/out-of-context token replay succeeded", "high"
        )
    if is_denied_status(manual_result.get("mutated_status")) or coerce_bool(
        manual_result.get("replay_rejected")
    ):
        return verdict("expected_behavior", 0.78, "replay was rejected", "info")
    return verdict(
        "needs_more_evidence",
        0.4,
        "replay result is inconclusive",
        "info",
        ["replay_succeeded or replay_rejected"],
    )


def evaluate_validation(manual_result: dict[str, Any]) -> dict[str, Any]:
    if coerce_bool(manual_result.get("disallowed_value_accepted")):
        return verdict(
            "confirmed", 0.82, "disallowed sink/path/template value was accepted", "medium"
        )
    if manual_result.get("validation_difference"):
        return verdict(
            "expected_behavior", 0.7, "disallowed value appears rejected or constrained", "info"
        )
    return verdict(
        "needs_more_evidence",
        0.4,
        "validation comparison is missing",
        "info",
        ["validation_difference"],
    )


def evaluate_manual(manual_result: dict[str, Any]) -> dict[str, Any]:
    if coerce_bool(manual_result.get("invariant_violated")):
        return verdict(
            "confirmed", 0.75, "manual result states the invariant was violated", "medium"
        )
    return verdict(
        "needs_more_evidence",
        0.35,
        "manual oracle requires explicit invariant evidence",
        "info",
        ["invariant_violated"],
    )


def verdict(
    status: str,
    confidence: float,
    reason: str,
    severity_hint: str,
    needs_more_evidence: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": confidence,
        "reason": reason,
        "severity_hint": severity_hint,
        "needs_more_evidence": needs_more_evidence or [],
    }
