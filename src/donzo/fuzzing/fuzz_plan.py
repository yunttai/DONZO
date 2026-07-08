from __future__ import annotations

from typing import Any

from donzo.fuzzing.models import compact_record, fuzz_plan_id
from donzo.models import stable_id

ORACLE_BY_CLASS = {
    "SQLI": "sqli_boolean_differential_oracle",
    "SSRF": "ssrf_oast_callback_oracle",
    "SSTI": "ssti_server_side_expression_evaluation_oracle",
    "BOLA": "bola_cross_actor_differential_oracle",
    "BFLA": "bfla_role_differential_state_change_oracle",
    "XSS": "xss_browser_execution_oracle",
    "COMMAND_INJECTION": "command_injection_safe_timing_oast_oracle",
    "PATH_TRAVERSAL": "path_traversal_known_safe_file_oracle",
    "XXE": "xxe_oast_external_entity_oracle",
    "FILE_UPLOAD": "file_upload_storage_rendering_oracle",
    "MASS_ASSIGNMENT": "mass_assignment_read_back_oracle",
    "EDE": "ede_field_diff_sensitivity_oracle",
    "BUSINESS_LOGIC": "business_logic_sequence_state_oracle",
}

PROBE_FAMILY_BY_CLASS = {
    "SQLI": "boolean_differential",
    "SSRF": "tester_controlled_oast_callback",
    "SSTI": "server_side_expression_evaluation",
    "BOLA": "cross_actor_differential",
    "BFLA": "role_differential_read_back",
    "XSS": "instrumented_browser_marker",
    "COMMAND_INJECTION": "safe_timing_or_oast",
    "PATH_TRAVERSAL": "known_safe_file_boundary",
    "XXE": "external_entity_oast",
    "FILE_UPLOAD": "benign_file_storage_rendering",
    "MASS_ASSIGNMENT": "benign_read_only_field_read_back",
    "EDE": "field_diff_contract_review",
    "BUSINESS_LOGIC": "sequence_state_transition",
}


def build_fuzz_plans(
    fuzz_candidates: list[dict[str, Any]],
    *,
    actor_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    plans = [build_fuzz_plan(candidate, actor_model=actor_model) for candidate in fuzz_candidates]
    return dedupe_by_id(plans, "fuzz_id")


def build_fuzz_plan(
    candidate: dict[str, Any],
    *,
    actor_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vulnerability_class = str(candidate.get("vulnerability_class") or "UNKNOWN").upper()
    endpoint_id = str(candidate.get("endpoint_id") or "")
    parameter = (
        candidate.get("target_parameter")
        if isinstance(candidate.get("target_parameter"), dict)
        else {}
    )
    fuzz_id = fuzz_plan_id(candidate)
    plan = {
        "fuzz_id": fuzz_id,
        "fuzz_candidate_id": candidate.get("fuzz_candidate_id"),
        "endpoint_id": endpoint_id,
        "method": candidate.get("method"),
        "path_template": candidate.get("path_template"),
        "vulnerability_class": vulnerability_class,
        "target_parameter": parameter,
        "preconditions": preconditions_for_class(vulnerability_class),
        "probe_family": PROBE_FAMILY_BY_CLASS.get(vulnerability_class, "manual_evidence"),
        "controls": controls_for_class(vulnerability_class),
        "oracle": ORACLE_BY_CLASS.get(vulnerability_class, "manual_fuzz_oracle"),
        "safety": safety_for_class(vulnerability_class),
        "confidence": candidate.get("confidence", 0.0),
        "manual_review_required": True,
        "execution_mode": "plan_only",
    }
    actor_context = actor_context_for_class(vulnerability_class, actor_model)
    if actor_context:
        plan["actor_context"] = actor_context
    return compact_record(plan)


def build_fuzz_oracle_templates(fuzz_plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    for plan in fuzz_plans:
        oracle_type = str(plan.get("oracle") or "manual_fuzz_oracle")
        templates.append(
            {
                "oracle_template_id": stable_id(
                    "fuzz_oracle_template", plan.get("fuzz_id"), oracle_type
                ),
                "fuzz_id": plan.get("fuzz_id"),
                "endpoint_id": plan.get("endpoint_id"),
                "vulnerability_class": plan.get("vulnerability_class"),
                "oracle_type": oracle_type,
                "required_observations": required_observations(oracle_type),
                "confirmed_if": confirmed_conditions(oracle_type),
                "false_positive_if": false_positive_conditions(oracle_type),
                "safety": plan.get("safety") or {},
            }
        )
    return templates


def preconditions_for_class(vulnerability_class: str) -> list[str]:
    common = ["authorized target", "stable baseline", "non-destructive mode"]
    if vulnerability_class == "SQLI":
        return common + ["read endpoint or test-owned data only", "control mutation available"]
    if vulnerability_class in {"SSRF", "XXE", "COMMAND_INJECTION"}:
        return common + ["OAST explicitly allowed by program policy before live use"]
    if vulnerability_class == "SSTI":
        return common + ["raw server response or generated artifact is captured"]
    if vulnerability_class == "BOLA":
        return [
            "user_A owns object_X",
            "user_B must not access object_X",
            "user_B can access own object of same type",
        ]
    if vulnerability_class == "BFLA":
        return [
            "privileged actor can perform baseline action",
            "lower-privilege actor must not perform action",
            "state-changing checks require read-back",
        ]
    if vulnerability_class in {"MASS_ASSIGNMENT", "BUSINESS_LOGIC", "FILE_UPLOAD"}:
        return common + ["use only seeded test-owned records", "read-back is available"]
    if vulnerability_class == "EDE":
        return [
            "authorized target",
            "response field inventory available",
            "UI/API contract notes available",
        ]
    return common


def controls_for_class(vulnerability_class: str) -> list[str]:
    if vulnerability_class == "SQLI":
        return ["baseline_repeat", "random_control_mutation", "syntax_control"]
    if vulnerability_class in {"SSRF", "XXE", "COMMAND_INJECTION"}:
        return ["baseline_repeat", "control_parameter_no_callback", "unique_token_match"]
    if vulnerability_class == "SSTI":
        return ["literal_control", "raw_response_capture", "client_side_rendering_excluded"]
    if vulnerability_class in {"BOLA", "BFLA"}:
        return ["baseline_actor_success", "comparison_actor_control", "read_back_for_mutations"]
    if vulnerability_class == "MASS_ASSIGNMENT":
        return ["legitimate_write_control", "read_back_control"]
    if vulnerability_class == "EDE":
        return ["ui_needed_fields", "caller_role_contract"]
    return ["baseline_repeat", "manual_review_control"]


def safety_for_class(vulnerability_class: str) -> dict[str, Any]:
    max_requests = 8
    blocked_actions = [
        "mass_id_enumeration",
        "destructive_mutation",
        "denial_of_service",
        "credential_attack",
        "malware_upload",
        "reverse_shell",
        "sensitive_file_read",
        "third_party_data_access",
    ]
    if vulnerability_class in {"BOLA", "BFLA", "MASS_ASSIGNMENT", "BUSINESS_LOGIC", "FILE_UPLOAD"}:
        max_requests = 12
    if vulnerability_class in {"SSRF", "XXE", "COMMAND_INJECTION"}:
        blocked_actions.append("cloud_metadata_access_without_explicit_authorization")
    return {
        "default_mode": "plan_only",
        "max_requests": max_requests,
        "destructive": False,
        "requires_test_accounts": vulnerability_class
        in {"BOLA", "BFLA", "MASS_ASSIGNMENT", "BUSINESS_LOGIC"},
        "requires_oast": vulnerability_class in {"SSRF", "XXE", "COMMAND_INJECTION"},
        "blocked_actions": blocked_actions,
        "manual_approval_required_for_live": True,
    }


def actor_context_for_class(
    vulnerability_class: str,
    actor_model: dict[str, Any] | None,
) -> dict[str, Any]:
    if vulnerability_class not in {"BOLA", "BFLA", "MASS_ASSIGNMENT", "BUSINESS_LOGIC"}:
        return {}
    actors = actor_model.get("actors") if actor_model else []
    actor_ids = [str(item.get("actor_id") or "") for item in actors if item.get("actor_id")]
    return {
        "available_actor_ids": actor_ids[:10],
        "requires_safe_credential_refs": True,
        "requires_seeded_test_data": True,
    }


def required_observations(oracle_type: str) -> list[str]:
    if oracle_type.startswith("sqli_"):
        return [
            "baseline_results",
            "control_results",
            "true_or_time_or_error_probe",
            "false_or_control_probe",
        ]
    if oracle_type.startswith("ssrf_") or oracle_type.startswith("xxe_"):
        return ["oast_interaction_token", "source_classification", "control_no_interaction"]
    if oracle_type.startswith("ssti_"):
        return ["raw_response", "literal_control", "evaluation_result"]
    if oracle_type.startswith(("bola_", "bfla_")):
        return ["actor_relationship_proof", "mutated_response", "read_back_for_state_changes"]
    if oracle_type.startswith("mass_assignment"):
        return ["submitted_fields", "read_back_fields"]
    if oracle_type.startswith("ede_"):
        return ["response_fields", "ui_needed_fields", "sensitive_unneeded_fields"]
    return ["baseline_results", "probe_results", "evidence_files"]


def confirmed_conditions(oracle_type: str) -> list[str]:
    return {
        "sqli_boolean_differential_oracle": [
            "baseline is stable",
            "true-like mutation stays baseline-like",
            "false-like mutation is consistently different",
            "control mutation does not explain the difference",
        ],
        "ssrf_oast_callback_oracle": [
            "OAST interaction token matches the original request",
            "interaction source is classified as server-side",
            "control request does not trigger interaction",
        ],
        "ssti_server_side_expression_evaluation_oracle": [
            "raw response or generated artifact contains server-side evaluation result",
            "literal control is not evaluated",
            "client-side rendering is excluded",
        ],
    }.get(oracle_type, ["oracle-specific evidence proves the security invariant was violated"])


def false_positive_conditions(oracle_type: str) -> list[str]:
    if oracle_type.startswith("sqli_"):
        return ["unstable baseline", "generic validation error", "WAF block page only"]
    if oracle_type.startswith("ssrf_"):
        return ["browser/client fetch", "proxy/link-preview interaction", "token mismatch"]
    if oracle_type.startswith("ssti_"):
        return ["client-side template rendering", "reflection without evaluation"]
    return ["preconditions not proven", "response-only signal without read-back when state matters"]


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
