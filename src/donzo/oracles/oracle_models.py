from __future__ import annotations

from typing import Any

from donzo.models import stable_id

ORACLE_STATUSES = {
    "confirmed",
    "probable",
    "not_reproducible",
    "needs_more_evidence",
    "expected_behavior",
    "false_positive",
    "out_of_scope",
    "blocked_by_safety_policy",
    "duplicate_candidate",
}


def oracle_result_record(
    *,
    test_plan: dict[str, Any],
    oracle_template: dict[str, Any],
    manual_result: dict[str, Any],
    verdict: dict[str, Any],
) -> dict[str, Any]:
    test_id = str(
        test_plan.get("test_id")
        or oracle_template.get("test_id")
        or manual_result.get("test_id")
        or ""
    )
    endpoint_id = str(
        test_plan.get("endpoint_id")
        or oracle_template.get("endpoint_id")
        or manual_result.get("endpoint_id")
        or ""
    )
    status = str(verdict.get("status") or "needs_more_evidence")
    if status not in ORACLE_STATUSES:
        status = "needs_more_evidence"
    return {
        "oracle_result_id": stable_id("oracle_result", test_id, endpoint_id, manual_result),
        "test_id": test_id,
        "endpoint_id": endpoint_id,
        "invariant_id": test_plan.get("invariant_id") or oracle_template.get("invariant_id"),
        "oracle_template_id": oracle_template.get("oracle_template_id"),
        "oracle_type": oracle_template.get("oracle_type")
        or (test_plan.get("oracle") or {}).get("type"),
        "manual_result": manual_result,
        "oracle_verdict": {
            "status": status,
            "confidence": verdict.get("confidence", 0.0),
            "reason": verdict.get("reason", ""),
            "severity_hint": verdict.get("severity_hint", "info"),
            "needs_more_evidence": verdict.get("needs_more_evidence", []),
        },
        "candidate_vulnerability": test_plan.get("candidate_vulnerability"),
        "evidence_files": manual_result.get("evidence_files") or [],
        "include_in_report": status == "confirmed",
    }


def coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "confirmed"}
    return bool(value)


def coerce_status(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_success_status(value: Any) -> bool:
    status = coerce_status(value)
    return status is not None and 200 <= status < 300


def is_denied_status(value: Any) -> bool:
    status = coerce_status(value)
    return status in {401, 403, 404}
