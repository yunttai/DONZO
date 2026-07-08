from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_safe_probes(fuzz_plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    for plan in fuzz_plans:
        probes.extend(probes_for_plan(plan))
    return probes


def probes_for_plan(plan: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerability_class = str(plan.get("vulnerability_class") or "").upper()
    builders = {
        "SQLI": sqli_probes,
        "SSRF": ssrf_probes,
        "SSTI": ssti_probes,
        "BOLA": bola_probes,
        "BFLA": bfla_probes,
        "XSS": xss_probes,
        "COMMAND_INJECTION": command_injection_probes,
        "PATH_TRAVERSAL": path_traversal_probes,
        "XXE": xxe_probes,
        "FILE_UPLOAD": file_upload_probes,
        "MASS_ASSIGNMENT": mass_assignment_probes,
        "EDE": ede_probes,
        "BUSINESS_LOGIC": business_logic_probes,
    }
    return builders.get(vulnerability_class, generic_probes)(plan)


def base_probe(plan: dict[str, Any], role: str, mutation_kind: str, **extra: Any) -> dict[str, Any]:
    probe = {
        "probe_id": stable_id("safe_probe", plan.get("fuzz_id"), role, mutation_kind),
        "fuzz_id": plan.get("fuzz_id"),
        "endpoint_id": plan.get("endpoint_id"),
        "vulnerability_class": plan.get("vulnerability_class"),
        "target_parameter": plan.get("target_parameter"),
        "probe_role": role,
        "mutation_kind": mutation_kind,
        "auto_execute": False,
        "destructive": False,
        "requires_manual_approval": True,
    }
    probe.update(extra)
    return probe


def baseline_probes(plan: dict[str, Any], count: int = 3) -> list[dict[str, Any]]:
    return [
        base_probe(plan, "baseline", f"baseline_repeat_{index}", expected_side_effect=False)
        for index in range(1, count + 1)
    ]


def sqli_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline_probes(plan) + [
        base_probe(plan, "control", "random_control_mutation", symbolic_value="DONZO_SQLI_CONTROL"),
        base_probe(
            plan, "mutation", "true_condition_marker", symbolic_value="DONZO_SQLI_TRUE_MARKER"
        ),
        base_probe(
            plan, "mutation", "false_condition_marker", symbolic_value="DONZO_SQLI_FALSE_MARKER"
        ),
    ]


def ssrf_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    token = stable_id("oast_token", plan.get("fuzz_id"))
    return baseline_probes(plan, 2) + [
        base_probe(plan, "control", "non_url_control", symbolic_value="DONZO_SSRF_CONTROL"),
        base_probe(
            plan,
            "mutation",
            "tester_controlled_unique_oast_url",
            oast_token=token,
            requires_oast=True,
            symbolic_value=f"https://oast.invalid/{token}",
        ),
    ]


def ssti_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline_probes(plan, 2) + [
        base_probe(
            plan, "control", "literal_template_control", symbolic_value="DONZO_SSTI_LITERAL"
        ),
        base_probe(
            plan, "mutation", "safe_expression_marker", symbolic_value="DONZO_SSTI_EXPR_7x7"
        ),
    ]


def bola_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        base_probe(plan, "baseline", "user_a_owned_object_read", actor="user_A"),
        base_probe(plan, "control", "user_b_own_object_read", actor="user_B"),
        base_probe(plan, "mutation", "user_b_requests_user_a_object", actor="user_B"),
        base_probe(plan, "read_back", "state_read_back_if_mutating", actor="user_A"),
    ]


def bfla_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        base_probe(plan, "baseline", "privileged_actor_action", actor="admin"),
        base_probe(plan, "mutation", "low_privilege_actor_action", actor="member"),
        base_probe(plan, "read_back", "privileged_state_read_back", actor="admin"),
    ]


def xss_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline_probes(plan, 2) + [
        base_probe(plan, "control", "plain_reflection_marker", symbolic_value="DONZO_XSS_CONTROL"),
        base_probe(
            plan, "mutation", "instrumented_browser_marker", symbolic_value="DONZO_XSS_MARKER"
        ),
    ]


def command_injection_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    token = stable_id("cmd_oast_token", plan.get("fuzz_id"))
    return baseline_probes(plan, 2) + [
        base_probe(plan, "control", "benign_argument_control", symbolic_value="DONZO_CMD_CONTROL"),
        base_probe(
            plan, "mutation", "safe_timing_marker", symbolic_value="DONZO_CMD_TIMING_MARKER"
        ),
        base_probe(
            plan, "mutation", "tester_controlled_oast_token", oast_token=token, requires_oast=True
        ),
    ]


def path_traversal_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline_probes(plan, 2) + [
        base_probe(plan, "control", "allowed_filename_control", symbolic_value="donzo-fixture.txt"),
        base_probe(
            plan, "mutation", "known_safe_boundary_marker", symbolic_value="DONZO_KNOWN_SAFE_FILE"
        ),
    ]


def xxe_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    token = stable_id("xxe_oast_token", plan.get("fuzz_id"))
    return baseline_probes(plan, 2) + [
        base_probe(plan, "control", "well_formed_xml_control", symbolic_value="DONZO_XML_CONTROL"),
        base_probe(
            plan, "mutation", "external_entity_oast_token", oast_token=token, requires_oast=True
        ),
    ]


def file_upload_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        base_probe(
            plan, "baseline", "legitimate_upload_control", symbolic_value="benign_fixture_upload"
        ),
        base_probe(
            plan, "mutation", "benign_content_type_boundary", symbolic_value="DONZO_UPLOAD_MARKER"
        ),
        base_probe(plan, "read_back", "stored_file_access_read_back"),
    ]


def mass_assignment_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    field = (plan.get("target_parameter") or {}).get("path") or "read_only_field"
    return [
        base_probe(plan, "baseline", "legitimate_write_body"),
        base_probe(plan, "mutation", "benign_read_only_field_submission", submitted_field=field),
        base_probe(plan, "read_back", "read_back_candidate_field", read_back_field=field),
    ]


def ede_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        base_probe(plan, "baseline", "authorized_response_capture"),
        base_probe(plan, "control", "ui_contract_field_inventory"),
    ]


def business_logic_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        base_probe(plan, "baseline", "normal_sequence_capture"),
        base_probe(plan, "mutation", "invalid_or_out_of_order_sequence"),
        base_probe(plan, "read_back", "state_transition_read_back"),
    ]


def generic_probes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return baseline_probes(plan, 2) + [
        base_probe(plan, "manual", "manual_evidence_capture"),
    ]
