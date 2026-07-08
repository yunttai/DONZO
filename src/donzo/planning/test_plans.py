from __future__ import annotations

from typing import Any

from donzo.actors import actor_context_for_endpoint
from donzo.models import stable_id


def build_safe_manual_test_plans(
    security_invariants: list[dict[str, Any]],
    *,
    api_endpoint_models: list[dict[str, Any]] | None = None,
    actor_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    endpoint_index = {
        str(item.get("endpoint_id") or ""): item for item in api_endpoint_models or []
    }
    plans: list[dict[str, Any]] = []
    for invariant in security_invariants:
        endpoint = endpoint_index.get(str(invariant.get("endpoint_id") or ""), {})
        plans.append(plan_for_invariant(invariant, endpoint, actor_model=actor_model))
    return dedupe_by_id(plans, "test_id")


def plan_for_invariant(
    invariant: dict[str, Any],
    endpoint: dict[str, Any],
    *,
    actor_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    invariant_type = str(invariant.get("type") or "generic")
    endpoint_id = str(invariant.get("endpoint_id") or "")
    test_id = stable_id("safe_manual_test", endpoint_id, invariant_type, invariant.get("statement"))
    base = {
        "test_id": test_id,
        "endpoint_id": endpoint_id,
        "invariant_id": invariant.get("invariant_id"),
        "candidate_vulnerability": invariant.get("candidate_vulnerability"),
        "safety": {
            "automatic_exploit": False,
            "authorized_scope_only": True,
            "requires_test_accounts": True,
            "no_real_user_data": True,
            "no_destructive_payloads": True,
        },
        "evidence_checklist": evidence_checklist(invariant_type),
        "oracle": oracle_for_type(invariant_type),
        "confidence": invariant.get("confidence", 0.0),
    }
    base.update(plan_body(invariant_type, endpoint, invariant))
    actor_context = invariant.get("actor_context") or actor_context_for_endpoint(
        endpoint, actor_model
    )
    if actor_context:
        base["actor_context"] = actor_context
        base["actor_strategy"] = actor_strategy_for_type(invariant_type, actor_context)
    return base


def plan_body(
    invariant_type: str,
    endpoint: dict[str, Any],
    invariant: dict[str, Any],
) -> dict[str, Any]:
    path_template = endpoint.get("path_template") or "target endpoint"
    if invariant_type in {"tenant_isolation", "object_ownership", "user_scope"}:
        return {
            "name": f"Cross-actor authorization check for {path_template}",
            "actor_model": (
                "user_A owns or can access the baseline object; user_B is a "
                "separate authorized test account without that relationship"
            ),
            "preconditions": [
                "Use only seeded non-sensitive records created for this test",
                "Record baseline authorized request/response for user_A",
                "Prepare user_B session that should not have access",
            ],
            "mutation": (
                "Replay the same request shape with user_B credentials and only "
                "the seeded object/tenant identifiers changed as required"
            ),
            "expected_secure_result": (
                "403, 404, or equivalent empty/denied response without target object data"
            ),
            "vulnerable_if": (
                "user_B receives success and response contains user_A/tenant-owned object data"
            ),
        }
    if invariant_type == "role_authorization":
        return {
            "name": f"Low-privilege function authorization check for {path_template}",
            "actor_model": (
                "admin_or_owner can perform baseline action; low_priv_user is a "
                "separate authorized test account"
            ),
            "preconditions": [
                "Create test role/permission fixture",
                "Capture baseline action with privileged account",
                "Ensure low_priv_user lacks the required role",
            ],
            "mutation": (
                "Repeat the same action with low_priv_user credentials against "
                "the seeded test object"
            ),
            "expected_secure_result": "403, 404, or explicit authorization failure",
            "vulnerable_if": "low_priv_user can perform or influence the privileged action",
        }
    if invariant_type == "field_allowlist":
        fields = (
            ", ".join(str(field) for field in invariant.get("fields") or [])
            or "read-only candidate fields"
        )
        return {
            "name": f"Mass-assignment allowlist check for {path_template}",
            "actor_model": "authorized owner account acting on its own seeded record",
            "preconditions": [
                "Use a seeded record owned by the test account",
                "Capture legitimate write request body",
                f"Select benign candidate fields: {fields}",
            ],
            "mutation": (
                "Add candidate read-only fields to the legitimate write body "
                "with harmless test values"
            ),
            "expected_secure_result": "fields are rejected, ignored, or unchanged after read-back",
            "vulnerable_if": "candidate fields are accepted and persisted after read-back",
        }
    if invariant_type in {"response_minimization", "response_field_minimization"}:
        fields = (
            ", ".join(str(field) for field in invariant.get("fields") or [])
            or "sensitive candidate fields"
        )
        return {
            "name": f"Excessive response data review for {path_template}",
            "actor_model": "authorized test account with expected normal access",
            "preconditions": [
                "Capture response for normal authorized UI/API flow",
                "Identify UI-visible fields or business-required fields when known",
            ],
            "mutation": (
                "No mutation; compare response fields against needed fields and role expectations"
            ),
            "expected_secure_result": f"response excludes or justifies candidate fields: {fields}",
            "vulnerable_if": (
                "response exposes unnecessary sensitive or privileged fields to the caller"
            ),
        }
    if invariant_type in {
        "sink_validation",
        "sink_sanitization",
        "callback_destination_validation",
        "file_path_constraint",
    }:
        return {
            "name": f"Sink input policy review for {path_template}",
            "actor_model": "authorized owner account acting on its own seeded record",
            "preconditions": [
                "Use only benign local/test URLs, paths, or filenames",
                "Do not use external callback collection unless explicitly authorized",
            ],
            "mutation": (
                "Submit allowed and clearly disallowed benign sink values and "
                "compare validation behavior"
            ),
            "expected_secure_result": (
                "disallowed destinations/paths/templates are rejected or normalized safely"
            ),
            "vulnerable_if": (
                "unsafe destination/path/template is accepted or later used by the application"
            ),
        }
    return {
        "name": f"State/business-rule review for {path_template}",
        "actor_model": "authorized test account using seeded non-sensitive objects",
        "preconditions": [
            "Capture normal successful workflow",
            "Prepare an invalid, replayed, or out-of-order workflow state",
        ],
        "mutation": (
            "Repeat, skip, or reorder a benign workflow step without high-rate "
            "or destructive behavior"
        ),
        "expected_secure_result": "invalid transition is rejected, ignored, or remains idempotent",
        "vulnerable_if": "invalid transition succeeds or changes protected state",
    }


def oracle_for_type(invariant_type: str) -> dict[str, Any]:
    mapping = {
        "tenant_isolation": "differential_body_oracle",
        "object_ownership": "differential_body_oracle",
        "user_scope": "differential_body_oracle",
        "role_authorization": "status_or_body_oracle",
        "function_level_authorization": "status_or_body_oracle",
        "field_allowlist": "mass_assignment_oracle",
        "read_only_field_protection": "mass_assignment_oracle",
        "response_minimization": "field_diff_oracle",
        "response_field_minimization": "field_diff_oracle",
        "sink_validation": "validation_oracle",
        "sink_sanitization": "validation_oracle",
        "callback_destination_validation": "validation_oracle",
        "file_path_constraint": "validation_oracle",
        "state_transition": "state_or_sequence_oracle",
        "server_side_price_calculation": "read_back_oracle",
        "server_side_quantity_validation": "read_back_oracle",
        "token_lifetime": "replay_oracle",
    }
    return {
        "type": mapping.get(invariant_type, "manual_evidence_oracle"),
        "manual_result_required": True,
    }


def actor_strategy_for_type(invariant_type: str, actor_context: dict[str, Any]) -> dict[str, Any]:
    baseline = str(actor_context.get("baseline_actor") or "user_A")
    comparison = str(actor_context.get("comparison_actor") or "user_B")
    privileged = str(actor_context.get("privileged_actor") or "admin")
    if invariant_type in {"role_authorization", "function_level_authorization"}:
        return {
            "baseline_actor": privileged or baseline,
            "mutation_actor": comparison,
            "relationship": "privileged actor succeeds; lower-privilege actor should be denied",
            "credential_refs_only": True,
        }
    if invariant_type in {"tenant_isolation", "object_ownership", "user_scope"}:
        return {
            "baseline_actor": baseline,
            "mutation_actor": comparison,
            "relationship": (
                "A/B authorized test accounts with different ownership or tenant relationship"
            ),
            "credential_refs_only": True,
        }
    return {
        "baseline_actor": baseline,
        "mutation_actor": baseline,
        "relationship": (
            "same authorized test actor uses seeded data while checking state/read-back behavior"
        ),
        "credential_refs_only": True,
    }


def evidence_checklist(invariant_type: str) -> list[str]:
    common = [
        "redacted baseline request",
        "redacted baseline response",
        "redacted mutated/manual-check request when applicable",
        "redacted mutated/manual-check response when applicable",
    ]
    if invariant_type in {
        "tenant_isolation",
        "object_ownership",
        "user_scope",
        "role_authorization",
    }:
        common.append("proof of actor relationship/role using only test accounts")
    if invariant_type == "field_allowlist":
        common.append("read-back response showing candidate fields unchanged or changed")
    if invariant_type == "response_minimization":
        common.append("field necessity notes or UI-visible field comparison")
    if invariant_type == "state_transition":
        common.append("before/after state evidence")
    return common


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
