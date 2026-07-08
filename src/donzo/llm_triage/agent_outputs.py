from __future__ import annotations

from typing import Any

from donzo.models import stable_id

AGENT_NAMES = {
    "api_modeler",
    "invariant_reviewer",
    "test_planner",
    "oracle_reviewer",
    "report_reviewer",
}

AGENT_VERDICTS = {
    "accept",
    "needs_more_evidence",
    "likely_false_positive",
    "out_of_scope_or_not_allowed",
}


def agent_output_envelope(
    *,
    agent: str,
    subject_id: str,
    subject_type: str,
    verdict: str,
    confidence: float,
    summary: str,
    evidence: list[str] | None = None,
    recommended_actions: list[str] | None = None,
    blocked_actions: list[str] | None = None,
) -> dict[str, Any]:
    normalized_agent = agent if agent in AGENT_NAMES else "api_modeler"
    normalized_verdict = verdict if verdict in AGENT_VERDICTS else "needs_more_evidence"
    return {
        "agent_output_id": stable_id(
            "llm_agent_output",
            normalized_agent,
            subject_type,
            subject_id,
            normalized_verdict,
        ),
        "agent": normalized_agent,
        "subject_id": subject_id,
        "subject_type": subject_type,
        "verdict": normalized_verdict,
        "confidence": clamp_confidence(confidence),
        "summary": summary or "No summary supplied.",
        "evidence": evidence or [],
        "recommended_actions": recommended_actions or [],
        "blocked_actions": blocked_actions
        or [
            "automatic exploit",
            "destructive testing",
            "credential attack",
            "secret validation",
            "out-of-scope probing",
        ],
    }


def build_agent_output_scaffolds(
    *,
    api_endpoint_models: list[dict[str, Any]] | None = None,
    security_invariants: list[dict[str, Any]] | None = None,
    safe_manual_test_plans: list[dict[str, Any]] | None = None,
    oracle_results: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []
    for endpoint in (api_endpoint_models or [])[:25]:
        outputs.append(
            agent_output_envelope(
                agent="api_modeler",
                subject_id=str(endpoint.get("endpoint_id") or ""),
                subject_type="api_endpoint_model",
                verdict="needs_more_evidence",
                confidence=float(endpoint.get("confidence") or 0.5),
                summary="Endpoint model is available for LLM review.",
                evidence=[str(endpoint.get("path_template") or endpoint.get("url") or "")],
            )
        )
    for invariant in (security_invariants or [])[:25]:
        outputs.append(
            agent_output_envelope(
                agent="invariant_reviewer",
                subject_id=str(invariant.get("invariant_id") or ""),
                subject_type="security_invariant",
                verdict="needs_more_evidence",
                confidence=float(invariant.get("confidence") or 0.5),
                summary=str(invariant.get("description") or "Security invariant needs review."),
                evidence=[str(invariant.get("invariant_type") or "")],
            )
        )
    for plan in (safe_manual_test_plans or [])[:25]:
        outputs.append(
            agent_output_envelope(
                agent="test_planner",
                subject_id=str(plan.get("test_id") or ""),
                subject_type="manual_test_plan",
                verdict="needs_more_evidence",
                confidence=float(plan.get("confidence") or 0.5),
                summary="Safe manual test plan is ready for review.",
                evidence=[str(plan.get("candidate_vulnerability") or "")],
            )
        )
    for result in oracle_results or []:
        oracle_verdict = result.get("oracle_verdict") or {}
        status = str(oracle_verdict.get("status") or "")
        verdict = "accept" if status == "confirmed" else "needs_more_evidence"
        outputs.append(
            agent_output_envelope(
                agent="oracle_reviewer",
                subject_id=str(result.get("oracle_result_id") or ""),
                subject_type="oracle_result",
                verdict=verdict,
                confidence=float(oracle_verdict.get("confidence") or 0.5),
                summary=str(oracle_verdict.get("reason") or "Oracle result needs review."),
                evidence=[str(item) for item in result.get("evidence_files") or []],
            )
        )
    for draft in report_drafts or []:
        outputs.append(
            agent_output_envelope(
                agent="report_reviewer",
                subject_id=str(draft.get("report_draft_id") or ""),
                subject_type="report_draft",
                verdict="needs_more_evidence",
                confidence=float(draft.get("confidence") or 0.5),
                summary=str(draft.get("summary") or "Report draft needs review."),
                evidence=[
                    str(item) for item in (draft.get("evidence") or {}).get("evidence_files") or []
                ],
            )
        )
    return [item for item in outputs if validate_agent_output(item)["valid"]]


def validate_agent_output(record: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if record.get("agent") not in AGENT_NAMES:
        errors.append("agent must be a known DONZO LLM agent")
    if record.get("verdict") not in AGENT_VERDICTS:
        errors.append("verdict must be a known LLM agent verdict")
    if not str(record.get("subject_id") or ""):
        errors.append("subject_id is required")
    if not str(record.get("subject_type") or ""):
        errors.append("subject_type is required")
    confidence = record.get("confidence")
    if not isinstance(confidence, int | float) or not 0 <= float(confidence) <= 1:
        errors.append("confidence must be between 0 and 1")
    if not isinstance(record.get("evidence"), list):
        errors.append("evidence must be an array")
    if not isinstance(record.get("recommended_actions"), list):
        errors.append("recommended_actions must be an array")
    if not isinstance(record.get("blocked_actions"), list) or not record.get("blocked_actions"):
        errors.append("blocked_actions must be a non-empty array")
    return {"valid": not errors, "errors": errors}


def clamp_confidence(value: object) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5
