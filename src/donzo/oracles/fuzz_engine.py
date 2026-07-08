from __future__ import annotations

from typing import Any

from donzo.fuzzing.baseline import build_baseline_set
from donzo.fuzzing.safety_policy import evaluate_fuzz_safety
from donzo.models import stable_id
from donzo.oracles.bfla import evaluate_bfla_role_differential
from donzo.oracles.bola import evaluate_bola_cross_actor
from donzo.oracles.business_logic import evaluate_business_logic_sequence_state
from donzo.oracles.command_injection import evaluate_command_injection_safe_timing_oast
from donzo.oracles.ede import evaluate_ede_field_diff
from donzo.oracles.file_upload import evaluate_file_upload_storage_rendering
from donzo.oracles.mass_assignment import evaluate_mass_assignment_read_back
from donzo.oracles.path_traversal import evaluate_path_traversal_known_safe_file
from donzo.oracles.sqli import (
    evaluate_sqli_boolean_differential,
    evaluate_sqli_error,
    evaluate_sqli_time_differential,
)
from donzo.oracles.ssrf import evaluate_ssrf_oast_callback
from donzo.oracles.ssti import evaluate_ssti_server_side_evaluation
from donzo.oracles.verdict import oracle_verdict
from donzo.oracles.xss import evaluate_xss_browser_execution
from donzo.oracles.xxe import evaluate_xxe_external_entity_oast
from donzo.reporting.finding_minimizer import build_confirmed_findings_from_fuzz_verdicts
from donzo.reporting.regression_case import build_fuzz_regression_cases


def evaluate_fuzz_oracle_results(
    fuzz_plans: list[dict[str, Any]],
    *,
    baseline_results: list[dict[str, Any]] | None = None,
    fuzz_results: list[dict[str, Any]] | None = None,
    oast_interactions: list[dict[str, Any]] | None = None,
    state_readback_results: list[dict[str, Any]] | None = None,
    mode: str = "plan_only",
    oast_enabled: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    baseline_results = baseline_results or []
    fuzz_results = fuzz_results or []
    oast_interactions = oast_interactions or []
    state_readback_results = state_readback_results or []
    verdicts: list[dict[str, Any]] = []
    for plan in fuzz_plans:
        verdicts.append(
            evaluate_fuzz_plan(
                plan,
                baseline_results=records_for_fuzz(baseline_results, plan),
                fuzz_results=records_for_fuzz(fuzz_results, plan),
                oast_interactions=records_for_fuzz(oast_interactions, plan),
                state_readback_results=records_for_fuzz(state_readback_results, plan),
                mode=mode,
                oast_enabled=oast_enabled,
            )
        )
    false_positive = build_false_positive_analysis(verdicts)
    confirmed = build_confirmed_findings_from_fuzz_verdicts(verdicts, fuzz_plans=fuzz_plans)
    regression = build_fuzz_regression_cases(verdicts, fuzz_plans=fuzz_plans)
    return {
        "oracle_verdicts": verdicts,
        "false_positive_analysis": false_positive,
        "confirmed_findings": confirmed,
        "regression_cases": regression,
    }


def evaluate_fuzz_plan(
    plan: dict[str, Any],
    *,
    baseline_results: list[dict[str, Any]],
    fuzz_results: list[dict[str, Any]],
    oast_interactions: list[dict[str, Any]],
    state_readback_results: list[dict[str, Any]],
    mode: str,
    oast_enabled: bool,
) -> dict[str, Any]:
    safety = evaluate_fuzz_safety(plan, mode=mode, oast_enabled=oast_enabled)
    if not safety["allowed"]:
        verdict = oracle_verdict(
            "blocked_by_safety_policy",
            1.0,
            "fuzz plan is blocked by safety policy",
            needs_more_evidence=safety["reasons"],
        )
        return verdict_record(plan, verdict, baseline_results, fuzz_results)

    baseline = build_baseline_set(
        baseline_results,
        fuzz_id=str(plan.get("fuzz_id") or ""),
        endpoint_id=str(plan.get("endpoint_id") or ""),
    )
    controls = role_records(fuzz_results, "control")
    mutations = role_records(fuzz_results, "mutation") or role_records(fuzz_results, "mutated")
    readbacks = role_records(fuzz_results, "read_back") + state_readback_results
    all_records = fuzz_results + state_readback_results
    vulnerability_class = str(plan.get("vulnerability_class") or "").upper()
    oracle_type = str(plan.get("oracle") or "")
    context = {"plan": plan, "target_parameter": plan.get("target_parameter") or {}}

    if vulnerability_class == "SQLI" and "time" in oracle_type:
        verdict = evaluate_sqli_time_differential(baseline, controls, mutations, context)
    elif vulnerability_class == "SQLI" and "error" in oracle_type:
        verdict = evaluate_sqli_error(baseline, controls, mutations, context)
    elif vulnerability_class == "SQLI":
        verdict = evaluate_sqli_boolean_differential(baseline, controls, mutations, context)
    elif vulnerability_class == "SSRF":
        verdict = evaluate_ssrf_oast_callback(mutations + controls, oast_interactions, context)
    elif vulnerability_class == "SSTI":
        verdict = evaluate_ssti_server_side_evaluation(controls, mutations, context)
    elif vulnerability_class == "BOLA":
        verdict = evaluate_bola_cross_actor(all_records, plan.get("actor_context") or {})
    elif vulnerability_class == "BFLA":
        verdict = evaluate_bfla_role_differential(all_records, plan.get("actor_context") or {})
    elif vulnerability_class == "XSS":
        verdict = evaluate_xss_browser_execution(controls, mutations, context)
    elif vulnerability_class == "COMMAND_INJECTION":
        verdict = evaluate_command_injection_safe_timing_oast(
            baseline_results,
            controls,
            mutations,
            oast_interactions,
            context,
        )
    elif vulnerability_class == "PATH_TRAVERSAL":
        verdict = evaluate_path_traversal_known_safe_file(controls, mutations, context)
    elif vulnerability_class == "XXE":
        verdict = evaluate_xxe_external_entity_oast(
            mutations + controls, oast_interactions, context
        )
    elif vulnerability_class == "FILE_UPLOAD":
        verdict = evaluate_file_upload_storage_rendering(all_records, context)
    elif vulnerability_class == "MASS_ASSIGNMENT":
        verdict = evaluate_mass_assignment_read_back(mutations + readbacks, context)
    elif vulnerability_class == "EDE":
        verdict = evaluate_ede_field_diff(baseline_results + all_records, context)
    elif vulnerability_class == "BUSINESS_LOGIC":
        verdict = evaluate_business_logic_sequence_state(all_records, context)
    else:
        verdict = oracle_verdict(
            "needs_more_evidence",
            0.3,
            "no vulnerability-specific oracle is registered for this fuzz plan",
            needs_more_evidence=["manual oracle selection"],
        )
    return verdict_record(plan, verdict, baseline_results, fuzz_results)


def verdict_record(
    plan: dict[str, Any],
    verdict: dict[str, Any],
    baseline_results: list[dict[str, Any]],
    fuzz_results: list[dict[str, Any]],
) -> dict[str, Any]:
    status = str(verdict.get("status") or "needs_more_evidence")
    fuzz_id = str(plan.get("fuzz_id") or "")
    endpoint_id = str(plan.get("endpoint_id") or "")
    return {
        "oracle_verdict_id": stable_id(
            "fuzz_oracle_verdict", fuzz_id, status, verdict.get("evidence")
        ),
        "fuzz_id": fuzz_id,
        "test_id": fuzz_id,
        "endpoint_id": endpoint_id,
        "vulnerability_class": plan.get("vulnerability_class"),
        "candidate_vulnerability": plan.get("vulnerability_class"),
        "oracle": plan.get("oracle"),
        "oracle_type": plan.get("oracle"),
        "verdict": status,
        "confidence": verdict.get("confidence", 0.0),
        "severity_hint": verdict.get("severity_hint", "info"),
        "evidence": verdict.get("evidence") or [],
        "needs_manual_review": status in {"confirmed", "probable", "needs_more_evidence"},
        "baseline_sample_count": len(baseline_results),
        "probe_result_count": len(fuzz_results),
        "false_positive_reasons": verdict.get("false_positive_reasons") or [],
        "include_in_report": status == "confirmed",
        "oracle_verdict": {
            "status": status,
            "confidence": verdict.get("confidence", 0.0),
            "reason": verdict.get("reason", ""),
            "severity_hint": verdict.get("severity_hint", "info"),
            "needs_more_evidence": verdict.get("needs_more_evidence") or [],
        },
    }


def records_for_fuzz(records: list[dict[str, Any]], plan: dict[str, Any]) -> list[dict[str, Any]]:
    fuzz_id = str(plan.get("fuzz_id") or "")
    endpoint_id = str(plan.get("endpoint_id") or "")
    return [
        item
        for item in records
        if (not item.get("fuzz_id") or str(item.get("fuzz_id")) == fuzz_id)
        and (not item.get("endpoint_id") or str(item.get("endpoint_id")) == endpoint_id)
    ]


def role_records(records: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    role = role.lower()
    return [
        item
        for item in records
        if role
        in str(
            item.get("probe_role") or item.get("role") or item.get("mutation_kind") or ""
        ).lower()
    ]


def build_false_positive_analysis(verdicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in verdicts:
        status = str(item.get("verdict") or "")
        reasons = item.get("false_positive_reasons") or []
        if (
            status not in {"false_positive", "expected_behavior", "blocked_by_safety_policy"}
            and not reasons
        ):
            continue
        output.append(
            {
                "analysis_id": stable_id(
                    "fuzz_false_positive", item.get("fuzz_id"), status, reasons
                ),
                "fuzz_id": item.get("fuzz_id"),
                "endpoint_id": item.get("endpoint_id"),
                "vulnerability_class": item.get("vulnerability_class"),
                "verdict": status,
                "reasons": reasons
                or (item.get("oracle_verdict") or {}).get("needs_more_evidence")
                or [str((item.get("oracle_verdict") or {}).get("reason") or "")],
            }
        )
    return output
