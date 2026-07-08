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


def build_fuzz_regression_cases(
    oracle_verdicts: list[dict[str, Any]],
    *,
    fuzz_plans: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    plan_index = {str(item.get("fuzz_id") or ""): item for item in fuzz_plans or []}
    cases: list[dict[str, Any]] = []
    for verdict in oracle_verdicts:
        if str(verdict.get("verdict") or "") != "confirmed":
            continue
        plan = plan_index.get(str(verdict.get("fuzz_id") or ""), {})
        oracle_type = str(
            verdict.get("oracle_type") or verdict.get("oracle") or plan.get("oracle") or "manual"
        )
        cases.append(
            {
                "regression_case_id": stable_id(
                    "fuzz_regression_case",
                    verdict.get("oracle_verdict_id"),
                    oracle_type,
                ),
                "source_oracle_result_id": verdict.get("oracle_verdict_id"),
                "fuzz_id": verdict.get("fuzz_id"),
                "test_id": verdict.get("test_id") or verdict.get("fuzz_id"),
                "endpoint_id": verdict.get("endpoint_id"),
                "oracle_type": oracle_type,
                "candidate_vulnerability": verdict.get("vulnerability_class"),
                "setup": setup_steps(plan),
                "action": action_steps(plan)
                or ["Replay the safe baseline/control/mutation sequence with seeded test data."],
                "expected_secure_behavior": expected_behavior_for_oracle(oracle_type),
                "assertions": assertions_for_oracle(oracle_type),
                "safety_constraints": [
                    "run only against local/staging or explicitly authorized test data",
                    "keep OAST disabled unless program policy explicitly allows it",
                    "do not use destructive payloads, sensitive file reads, or enumeration",
                ],
            }
        )
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
    if oracle_type.startswith("sqli_"):
        return "Parameterized input does not affect query structure, timing, or SQL error behavior."
    if oracle_type.startswith("ssrf_"):
        return (
            "Server rejects or constrains external callback destinations; no OAST callback occurs."
        )
    if oracle_type.startswith("ssti_"):
        return "Template-like input is treated as data and is not evaluated server-side."
    if oracle_type.startswith("bola_"):
        return "Cross-actor object access is denied or returns only authorized data."
    if oracle_type.startswith("bfla_"):
        return "Lower-privilege actors cannot perform privileged functions or change state."
    if oracle_type.startswith("xss_"):
        return "User-controlled text is encoded or sanitized and does not execute in the browser."
    if oracle_type.startswith("command_injection_"):
        return "Command-like input is treated as data; no timing or OAST execution signal occurs."
    if oracle_type.startswith("path_traversal_"):
        return "Path inputs remain constrained to authorized fixture boundaries."
    if oracle_type.startswith("xxe_"):
        return "XML parsing does not resolve external entities or produce OAST callbacks."
    if oracle_type.startswith("file_upload_"):
        return "Uploaded benign files are stored, rendered, and authorized safely."
    if oracle_type.startswith("ede_"):
        return "Responses contain only fields required for the caller role and workflow."
    if oracle_type.startswith("business_logic_"):
        return "Invalid or out-of-order business sequences do not change protected state."
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
    if oracle_type.startswith("sqli_"):
        return ["baseline/control/mutation responses remain equivalent for query semantics"]
    if oracle_type.startswith("ssrf_") or oracle_type.startswith("xxe_"):
        return ["no matching OAST interaction is recorded for the unique token"]
    if oracle_type.startswith("ssti_"):
        return [
            "raw response contains literal input or safely escaped output, not evaluated output"
        ]
    if oracle_type.startswith("bola_"):
        return ["comparison actor receives 401/403/404 or no protected object data"]
    if oracle_type.startswith("bfla_"):
        return ["lower-privilege action is denied and read-back confirms no state change"]
    if oracle_type.startswith("mass_assignment"):
        return ["read-back response does not contain unexpected persisted fields"]
    if oracle_type.startswith("ede_"):
        return ["sensitive unneeded fields are absent from the response"]
    if oracle_type.startswith("business_logic_"):
        return ["protected state is unchanged after invalid sequence"]
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
