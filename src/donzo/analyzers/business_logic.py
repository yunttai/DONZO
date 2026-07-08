from __future__ import annotations

from typing import Any

from donzo.models import stable_id

FLOW_PATTERNS = {
    "invitation": ("invite", "invitation"),
    "password_reset": ("password_reset", "reset_password", "forgot", "reset"),
    "email_verification": ("verify_email", "email_verification", "verification", "confirm_email"),
    "checkout_payment": ("checkout", "payment", "pay", "invoice", "billing"),
    "coupon": ("coupon", "discount", "promo"),
    "refund": ("refund", "chargeback", "return"),
    "subscription": ("subscription", "plan", "billing"),
    "file_sharing": ("share", "file", "attachment", "upload", "download"),
    "approval_workflow": ("approve", "approval", "reject", "review"),
    "role_change": ("role", "permission", "admin", "owner"),
    "oauth": ("oauth", "authorize", "callback", "sso"),
}

MUTATION_STRATEGIES = {
    "invitation": ("repeat", "accept-after-revoke", "reuse-expired-token"),
    "password_reset": ("repeat", "replay", "reuse-expired-token"),
    "email_verification": ("repeat", "replay", "reuse-expired-token"),
    "checkout_payment": ("skip", "reorder", "confirm-before-payment", "repeat"),
    "coupon": ("repeat", "replay"),
    "refund": ("repeat", "reorder"),
    "subscription": ("skip", "reorder", "repeat"),
    "file_sharing": ("replay", "accept-after-revoke"),
    "approval_workflow": ("skip", "reorder", "repeat"),
    "role_change": ("replay", "reorder"),
    "oauth": ("replay", "reuse-expired-token"),
}


def build_business_flow_models(
    api_endpoint_models: list[dict[str, Any]],
    *,
    api_sequences: list[dict[str, Any]] | None = None,
    state_transitions: list[dict[str, Any]] | None = None,
    graphql_operations: list[dict[str, Any]] | None = None,
    actor_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    evidence_items = endpoint_evidence(api_endpoint_models) + graphql_evidence(
        graphql_operations or []
    )
    flows: list[dict[str, Any]] = []
    for flow_type, markers in FLOW_PATTERNS.items():
        matched = [
            item for item in evidence_items if any(marker in item["text"] for marker in markers)
        ]
        if not matched:
            continue
        flow_id = stable_id("business_flow", flow_type, [item["endpoint_id"] for item in matched])
        flows.append(
            {
                "business_flow_id": flow_id,
                "flow_type": flow_type,
                "name": flow_type.replace("_", " "),
                "endpoint_ids": sorted(dict.fromkeys(item["endpoint_id"] for item in matched))[:50],
                "operation_names": sorted(
                    dict.fromkeys(
                        item.get("operation_name", "")
                        for item in matched
                        if item.get("operation_name")
                    )
                ),
                "actor_context": actor_model.get("summary")
                if isinstance(actor_model, dict)
                else {},
                "state_transition_refs": matching_transition_refs(matched, state_transitions or []),
                "sequence_refs": matching_sequence_refs(matched, api_sequences or []),
                "evidence": sorted(dict.fromkeys(item["evidence"] for item in matched))[:50],
                "confidence": flow_confidence(matched),
            }
        )
    return flows


def build_business_state_invariants(
    business_flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    invariants: list[dict[str, Any]] = []
    for flow in business_flows:
        endpoint_id = first_endpoint(flow)
        flow_type = str(flow.get("flow_type") or "business_flow")
        for invariant_type, statement, vulnerability in invariant_templates(flow_type):
            invariants.append(
                {
                    "invariant_id": stable_id(
                        "business_invariant", flow.get("business_flow_id"), invariant_type
                    ),
                    "endpoint_id": endpoint_id,
                    "business_flow_id": flow.get("business_flow_id"),
                    "type": invariant_type,
                    "statement": statement,
                    "severity_if_violated": severity_for_flow(flow_type),
                    "candidate_vulnerability": vulnerability,
                    "confidence": min(0.86, float(flow.get("confidence") or 0.6) + 0.08),
                    "evidence": list(flow.get("evidence") or [])[:20],
                    "actor_context": flow.get("actor_context") or {},
                }
            )
    return invariants


def build_business_mutation_plans(
    business_flows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    for flow in business_flows:
        flow_type = str(flow.get("flow_type") or "")
        for strategy in MUTATION_STRATEGIES.get(flow_type, ("repeat", "reorder")):
            plans.append(
                {
                    "business_mutation_plan_id": stable_id(
                        "business_mutation_plan",
                        flow.get("business_flow_id"),
                        strategy,
                    ),
                    "business_flow_id": flow.get("business_flow_id"),
                    "flow_type": flow_type,
                    "strategy": strategy,
                    "auto_execute": False,
                    "safety": {
                        "manual_only": True,
                        "authorized_test_accounts_only": True,
                        "non_destructive": True,
                        "no_high_rate": True,
                    },
                    "preconditions": [
                        "Use seeded non-sensitive objects only",
                        "Capture a successful baseline flow before manual mutation",
                        "Do not reuse real user data or production secrets",
                    ],
                    "manual_mutation": mutation_description(flow_type, strategy),
                    "expected_secure_result": expected_secure_result(strategy),
                    "evidence": list(flow.get("evidence") or [])[:20],
                }
            )
    return plans


def endpoint_evidence(api_endpoint_models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for endpoint in api_endpoint_models:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        text = " ".join(
            [
                endpoint_id,
                str(endpoint.get("path_template") or ""),
                str(endpoint.get("resource") or ""),
                str(endpoint.get("action") or ""),
                " ".join(str(tag) for tag in endpoint.get("risk_tags") or []),
            ]
        ).lower()
        output.append(
            {
                "endpoint_id": endpoint_id,
                "text": text,
                "evidence": f"api_endpoint:{endpoint_id}",
            }
        )
    return output


def graphql_evidence(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for operation in operations:
        endpoint_id = str(operation.get("logical_endpoint_id") or "")
        text = " ".join(
            [
                endpoint_id,
                str(operation.get("operation_name") or ""),
                str(operation.get("resource") or ""),
                str(operation.get("action") or ""),
                " ".join(str(field) for field in operation.get("fields") or []),
                " ".join(str(name) for name in operation.get("variable_names") or []),
            ]
        ).lower()
        output.append(
            {
                "endpoint_id": endpoint_id,
                "operation_name": operation.get("operation_name"),
                "text": text,
                "evidence": f"graphql_operation:{operation.get('graphql_operation_id')}",
            }
        )
    return output


def invariant_templates(flow_type: str) -> list[tuple[str, str, str]]:
    if flow_type in {"invitation", "password_reset", "email_verification", "oauth"}:
        return [
            (
                "token_lifetime",
                "one-time tokens must expire, be bound to the intended actor and "
                "action, and reject replay",
                "replay or token misuse",
            ),
            (
                "state_transition",
                "flow state must reject skipped, repeated, or out-of-order completion",
                "business logic flaw",
            ),
        ]
    if flow_type in {"checkout_payment", "coupon", "refund", "subscription"}:
        return [
            (
                "server_side_price_calculation",
                "monetary effects must be calculated or verified server-side across the whole flow",
                "business logic flaw",
            ),
            (
                "state_transition",
                "payment/refund/subscription state must reject skip, repeat, "
                "reorder, and replay attempts",
                "business logic flaw",
            ),
        ]
    if flow_type in {"approval_workflow", "role_change"}:
        return [
            (
                "role_authorization",
                "only authorized actors may approve, reject, or alter roles/permissions",
                "BFLA / privilege escalation",
            ),
            (
                "state_transition",
                "approval or role-change flow must enforce current-state and actor preconditions",
                "business logic flaw",
            ),
        ]
    return [
        (
            "state_transition",
            "business flow must enforce current-state, replay, and authorization checks",
            "business logic flaw",
        )
    ]


def matching_transition_refs(
    matched: list[dict[str, Any]],
    state_transitions: list[dict[str, Any]],
) -> list[str]:
    endpoint_ids = {item["endpoint_id"] for item in matched}
    refs = [
        str(item.get("transition_id"))
        for item in state_transitions
        if item.get("from_endpoint") in endpoint_ids or item.get("to_endpoint") in endpoint_ids
    ]
    return sorted(dict.fromkeys(ref for ref in refs if ref))[:50]


def matching_sequence_refs(
    matched: list[dict[str, Any]],
    api_sequences: list[dict[str, Any]],
) -> list[str]:
    endpoint_ids = {item["endpoint_id"] for item in matched}
    refs = []
    for sequence in api_sequences:
        if any(step.get("endpoint_id") in endpoint_ids for step in sequence.get("steps") or []):
            refs.append(str(sequence.get("sequence_id")))
    return sorted(dict.fromkeys(ref for ref in refs if ref))[:50]


def first_endpoint(flow: dict[str, Any]) -> str:
    endpoint_ids = flow.get("endpoint_ids") or []
    return str(endpoint_ids[0]) if endpoint_ids else str(flow.get("business_flow_id") or "")


def severity_for_flow(flow_type: str) -> str:
    if flow_type in {"role_change", "checkout_payment", "refund", "oauth"}:
        return "high"
    return "medium"


def flow_confidence(matched: list[dict[str, Any]]) -> float:
    return round(min(0.9, 0.52 + len(matched) * 0.06), 2)


def mutation_description(flow_type: str, strategy: str) -> str:
    flow_name = flow_type.replace("_", " ")
    return (
        f"Manually try {strategy} against the seeded {flow_name} flow without "
        "automated payloading or high-rate traffic."
    )


def expected_secure_result(strategy: str) -> str:
    if strategy in {"reuse-expired-token", "accept-after-revoke", "confirm-before-payment"}:
        return "request is rejected with 400/401/403/404/409/422 or leaves state unchanged"
    if strategy in {"skip", "reorder"}:
        return "out-of-order flow is rejected or remains idempotent"
    return "repeat/replay is rejected, idempotent, or produces no unauthorized state change"
