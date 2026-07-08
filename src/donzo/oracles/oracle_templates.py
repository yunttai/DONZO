from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_oracle_templates(test_plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    for plan in test_plans:
        oracle = plan.get("oracle") if isinstance(plan.get("oracle"), dict) else {}
        oracle_type = str(oracle.get("type") or "manual_evidence_oracle")
        templates.append(
            {
                "oracle_template_id": stable_id(
                    "oracle_template", plan.get("test_id"), oracle_type
                ),
                "test_id": plan.get("test_id"),
                "endpoint_id": plan.get("endpoint_id"),
                "invariant_id": plan.get("invariant_id"),
                "oracle_type": oracle_type,
                "required_manual_fields": required_manual_fields(oracle_type),
                "confirmed_if": confirmed_conditions(oracle_type),
                "not_reproducible_if": not_reproducible_conditions(oracle_type),
                "needs_more_evidence_if": [
                    "required evidence files are missing",
                    "actor ownership/role relationship is not documented",
                    "response/body/state comparison is ambiguous",
                ],
                "safety": plan.get("safety") or {},
            }
        )
    return templates


def required_manual_fields(oracle_type: str) -> list[str]:
    common = ["baseline_status", "mutated_status", "evidence_files", "notes"]
    if oracle_type == "differential_body_oracle":
        return common + [
            "baseline_body_summary",
            "mutated_body_summary",
            "actor_relationship_proof",
        ]
    if oracle_type == "mass_assignment_oracle":
        return common + ["submitted_fields", "read_back_fields", "persisted_unexpected_fields"]
    if oracle_type == "field_diff_oracle":
        return [
            "response_fields",
            "ui_needed_fields",
            "sensitive_unneeded_fields",
            "evidence_files",
            "notes",
        ]
    if oracle_type == "state_or_sequence_oracle":
        return common + ["before_state", "after_state", "expected_state"]
    if oracle_type == "validation_oracle":
        return common + ["accepted_value", "rejected_value", "validation_difference"]
    return common


def confirmed_conditions(oracle_type: str) -> list[str]:
    if oracle_type == "differential_body_oracle":
        return [
            "mutated_status is 2xx",
            "mutated response contains object/user/tenant data that should belong to another actor",
            "actor relationship proof shows access should be denied",
        ]
    if oracle_type == "mass_assignment_oracle":
        return [
            "candidate read-only field was submitted with a benign test value",
            "read-back confirms the candidate field changed or influenced protected state",
        ]
    if oracle_type == "field_diff_oracle":
        return [
            "response contains sensitive or privileged fields",
            "fields are not needed by the visible UI or documented caller role",
        ]
    if oracle_type == "state_or_sequence_oracle":
        return [
            "invalid/replayed/out-of-order sequence succeeds",
            "protected state changes contrary to expected workflow",
        ]
    if oracle_type == "validation_oracle":
        return [
            "disallowed sink value is accepted",
            "accepted value can be observed later in application behavior",
        ]
    return ["manual evidence demonstrates invariant violation"]


def not_reproducible_conditions(oracle_type: str) -> list[str]:
    if oracle_type in {"differential_body_oracle", "status_or_body_oracle"}:
        return ["mutated_status is 401/403/404 or equivalent denied response"]
    if oracle_type == "mass_assignment_oracle":
        return ["read-back confirms candidate fields were rejected, ignored, or unchanged"]
    if oracle_type == "field_diff_oracle":
        return ["candidate fields are absent or justified for the caller role/UI"]
    if oracle_type == "state_or_sequence_oracle":
        return ["invalid transition is rejected, ignored, or idempotent"]
    return ["manual check matches expected secure result"]
