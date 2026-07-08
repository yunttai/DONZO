from __future__ import annotations

from typing import Any

from donzo.models import now_utc, stable_id


def build_report_drafts(
    oracle_results: list[dict[str, Any]],
    *,
    test_plans: list[dict[str, Any]] | None = None,
    security_invariants: list[dict[str, Any]] | None = None,
    api_endpoint_models: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    plan_index = {str(item.get("test_id") or ""): item for item in test_plans or []}
    invariant_index = {
        str(item.get("invariant_id") or ""): item for item in security_invariants or []
    }
    endpoint_index = {
        str(item.get("endpoint_id") or ""): item for item in api_endpoint_models or []
    }
    drafts: list[dict[str, Any]] = []
    for result in oracle_results:
        verdict = result.get("oracle_verdict") or {}
        if verdict.get("status") != "confirmed":
            continue
        test_id = str(result.get("test_id") or "")
        endpoint_id = str(result.get("endpoint_id") or "")
        plan = plan_index.get(test_id, {})
        invariant = invariant_index.get(str(result.get("invariant_id") or ""), {})
        endpoint = endpoint_index.get(endpoint_id, {})
        drafts.append(
            report_draft_record(result, plan=plan, invariant=invariant, endpoint=endpoint)
        )
    return drafts


def report_draft_record(
    oracle_result: dict[str, Any],
    *,
    plan: dict[str, Any],
    invariant: dict[str, Any],
    endpoint: dict[str, Any],
) -> dict[str, Any]:
    manual_result = oracle_result.get("manual_result") or {}
    verdict = oracle_result.get("oracle_verdict") or {}
    endpoint_label = endpoint_label_from(endpoint, plan, oracle_result)
    vulnerability = (
        oracle_result.get("candidate_vulnerability")
        or plan.get("candidate_vulnerability")
        or invariant.get("candidate_vulnerability")
        or "security invariant violation"
    )
    evidence_files = [str(item) for item in oracle_result.get("evidence_files") or []]
    steps = safe_steps(plan, manual_result)
    return {
        "report_draft_id": stable_id(
            "report_draft",
            oracle_result.get("oracle_result_id"),
            endpoint_label,
        ),
        "oracle_result_id": oracle_result.get("oracle_result_id"),
        "test_id": oracle_result.get("test_id"),
        "endpoint_id": oracle_result.get("endpoint_id"),
        "title": f"{vulnerability} on {endpoint_label}",
        "severity_hint": verdict.get("severity_hint", "medium"),
        "confidence": verdict.get("confidence", 0.0),
        "affected_endpoint": endpoint_label,
        "violated_invariants": violated_invariants(invariant, oracle_result),
        "summary": verdict.get("reason")
        or "Manual oracle confirmed a security invariant violation.",
        "steps_to_reproduce": steps,
        "impact": impact_text(vulnerability, invariant),
        "evidence": {
            "oracle_reason": verdict.get("reason", ""),
            "manual_result_fields": compact_manual_result(manual_result),
            "evidence_files": evidence_files,
        },
        "recommended_fix": recommended_fix_text(invariant, vulnerability),
        "safety_notes": [
            "Use only authorized test accounts and seeded non-sensitive records.",
            "Do not include secrets, live credentials, or real user data in the final report.",
            "Do not automate exploit attempts from this draft.",
        ],
        "generated_at": now_utc(),
    }


def endpoint_label_from(
    endpoint: dict[str, Any],
    plan: dict[str, Any],
    oracle_result: dict[str, Any],
) -> str:
    method = str(endpoint.get("method") or plan.get("method") or "").upper()
    path = (
        endpoint.get("path_template")
        or endpoint.get("url")
        or plan.get("path_template")
        or plan.get("target")
        or oracle_result.get("endpoint_id")
        or "unknown endpoint"
    )
    return f"{method} {path}".strip()


def violated_invariants(
    invariant: dict[str, Any],
    oracle_result: dict[str, Any],
) -> list[dict[str, Any]]:
    if invariant:
        return [
            {
                "invariant_id": invariant.get("invariant_id"),
                "type": invariant.get("invariant_type"),
                "description": invariant.get("description"),
            }
        ]
    return [
        {
            "invariant_id": oracle_result.get("invariant_id"),
            "type": "unknown",
            "description": "Confirmed by manual oracle result.",
        }
    ]


def safe_steps(plan: dict[str, Any], manual_result: dict[str, Any]) -> list[str]:
    steps = [str(item) for item in plan.get("manual_steps") or plan.get("steps") or []]
    if not steps and manual_result.get("steps_performed"):
        steps = [str(item) for item in manual_result.get("steps_performed") or []]
    if not steps:
        steps = [
            "Prepare two authorized test accounts and non-sensitive seeded test records.",
            "Replay the documented request manually with the changed test-only condition.",
            "Compare status, response body, and read-back state against the expected invariant.",
        ]
    return steps


def compact_manual_result(manual_result: dict[str, Any]) -> dict[str, Any]:
    hidden = {"headers", "cookies", "authorization", "raw_request", "raw_response"}
    return {
        str(key): value
        for key, value in manual_result.items()
        if str(key).lower() not in hidden and value not in (None, "", [], {})
    }


def impact_text(vulnerability: str, invariant: dict[str, Any]) -> str:
    invariant_type = str(invariant.get("invariant_type") or "").replace("_", " ")
    if invariant_type:
        return f"Violation of {invariant_type} can allow unauthorized state or data access."
    return f"{vulnerability} can impact authorization, data exposure, or workflow integrity."


def recommended_fix_text(invariant: dict[str, Any], vulnerability: str) -> str:
    description = str(invariant.get("description") or "").strip()
    if description:
        return f"Enforce the invariant server-side: {description}"
    return f"Add server-side validation and authorization checks for {vulnerability}."
