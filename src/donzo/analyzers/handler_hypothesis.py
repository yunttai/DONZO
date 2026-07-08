from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_handler_hypotheses(
    api_endpoint_models: list[dict[str, Any]],
    *,
    parameter_classifications: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, Any] | None = None,
    schema_diffs: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    classification_index = classifications_by_endpoint(parameter_classifications or [])
    graph_edges = dependency_graph.get("edges") if isinstance(dependency_graph, dict) else []
    output: list[dict[str, Any]] = []
    for endpoint in api_endpoint_models:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        parameters = classification_index.get(endpoint_id, [])
        related_diffs = [
            item
            for item in schema_diffs or []
            if item.get("read_endpoint") == endpoint_id or item.get("write_endpoint") == endpoint_id
        ]
        related_edges = [
            item
            for item in graph_edges or []
            if isinstance(item, dict)
            and (item.get("from") == endpoint_id or item.get("to") == endpoint_id)
        ]
        hypothesis = {
            "authn": authn_steps(endpoint),
            "input_parsing": input_parsing_steps(endpoint, parameters),
            "validation": validation_steps(parameters),
            "authorization": authorization_steps(endpoint, parameters),
            "business_logic": business_logic_steps(endpoint, related_edges),
            "storage_or_internal_call": storage_steps(endpoint),
            "serialization": serialization_steps(endpoint, parameters),
        }
        output.append(
            {
                "hypothesis_id": stable_id("handler_hypothesis", endpoint_id),
                "endpoint_id": endpoint_id,
                "method": endpoint.get("method"),
                "path_template": endpoint.get("path_template"),
                "resource": endpoint.get("resource"),
                "action": endpoint.get("action"),
                "handler_hypothesis": hypothesis,
                "missing_check_candidates": missing_check_candidates(
                    endpoint, parameters, related_diffs
                ),
                "evidence": {
                    "parameter_count": len(parameters),
                    "schema_diff_count": len(related_diffs),
                    "dependency_edge_count": len(related_edges),
                },
                "confidence": hypothesis_confidence(
                    endpoint, parameters, related_diffs, related_edges
                ),
            }
        )
    return output


def authn_steps(endpoint: dict[str, Any]) -> list[str]:
    if endpoint.get("auth_required") is True:
        return ["authenticate bearer/session token before handler logic"]
    return ["authentication requirement is unknown from passive evidence"]


def input_parsing_steps(endpoint: dict[str, Any], parameters: list[dict[str, Any]]) -> list[str]:
    steps: list[str] = []
    for name in endpoint.get("path_params") or []:
        steps.append(f"parse path parameter {name}")
    for name in endpoint.get("query_params") or []:
        steps.append(f"parse query parameter {name}")
    for parameter in parameters:
        if parameter.get("location") == "body":
            steps.append(f"parse body field {parameter.get('path') or parameter.get('name')}")
    return steps or ["parse request method, path, query, headers, and body"]


def validation_steps(parameters: list[dict[str, Any]]) -> list[str]:
    steps: list[str] = []
    for parameter in parameters:
        semantic = str(parameter.get("semantic_class") or "")
        name = str(parameter.get("name") or parameter.get("path") or "")
        if semantic in {"object_identifier", "tenant_identifier", "user_identifier"}:
            steps.append(f"validate {name} is well-formed and refers to an existing object")
        elif semantic in {"role_field", "permission_field", "privilege_flag"}:
            steps.append(f"validate {name} is an allowed role or permission value")
        elif semantic == "state_field":
            steps.append(f"validate {name} is an allowed state transition")
        elif semantic in {"url_field", "callback_field", "webhook_field"}:
            steps.append(f"validate {name} against allowed destination policy")
        elif semantic in {"file_field", "path_field", "template_field"}:
            steps.append(f"validate {name} cannot escape the intended storage/template boundary")
    return dedupe(steps)


def authorization_steps(endpoint: dict[str, Any], parameters: list[dict[str, Any]]) -> list[str]:
    steps: list[str] = []
    has_tenant = any(item.get("semantic_class") == "tenant_identifier" for item in parameters)
    has_object = any(item.get("semantic_class") == "object_identifier" for item in parameters)
    has_user = any(item.get("semantic_class") == "user_identifier" for item in parameters)
    has_role = any(
        item.get("semantic_class") in {"role_field", "permission_field", "privilege_flag"}
        for item in parameters
    )
    if has_tenant:
        steps.append("caller must belong to the tenant/workspace/org referenced by the request")
    if has_object:
        steps.append(
            "caller must be authorized to access the "
            f"{endpoint.get('resource') or 'resource'} object"
        )
    if has_tenant and has_object:
        steps.append("object identifier must belong to the referenced tenant identifier")
    if has_user:
        steps.append("caller must be the referenced user or have delegated/admin permission")
    if has_role:
        steps.append("caller role must permit this function-level action")
    if endpoint.get("side_effect") is True and not steps:
        steps.append("caller must be authorized to perform this state-changing action")
    return dedupe(steps)


def business_logic_steps(endpoint: dict[str, Any], graph_edges: list[dict[str, Any]]) -> list[str]:
    resource = endpoint.get("resource") or "resource"
    action = endpoint.get("action") or endpoint.get("operation_type") or "handle"
    steps = [f"{action} {resource} according to application workflow"]
    if graph_edges:
        steps.append("honor observed producer-consumer and sequence dependencies")
    return steps


def storage_steps(endpoint: dict[str, Any]) -> list[str]:
    resource = str(endpoint.get("resource") or "resource")
    action = str(endpoint.get("action") or endpoint.get("operation_type") or "handle")
    return [f"{resource}Service.{action}({resource}Context)"]


def serialization_steps(endpoint: dict[str, Any], parameters: list[dict[str, Any]]) -> list[str]:
    if str(endpoint.get("operation_type") or "") != "read":
        return ["return state-changing result with only fields appropriate for caller"]
    sensitive = [
        str(item.get("name") or item.get("path") or "")
        for item in parameters
        if item.get("location") == "response"
        and item.get("semantic_class")
        in {"email_field", "sensitive_field", "money_field", "role_field", "permission_field"}
    ]
    if sensitive:
        return [f"serialize response DTO without unauthorized fields: {', '.join(sensitive[:8])}"]
    return ["serialize response DTO appropriate for caller role and ownership"]


def missing_check_candidates(
    endpoint: dict[str, Any],
    parameters: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    has_tenant = any(item.get("semantic_class") == "tenant_identifier" for item in parameters)
    has_object = any(item.get("semantic_class") == "object_identifier" for item in parameters)
    if has_tenant:
        candidates.append(check("caller belongs to tenant", "BOLA / cross-tenant access", 0.78))
    if has_object:
        candidates.append(check("caller is authorized for object id", "BOLA / IDOR", 0.76))
    if has_tenant and has_object:
        candidates.append(check("object id belongs to tenant id", "BOLA / tenant confusion", 0.86))
    if any(
        item.get("semantic_class") in {"role_field", "permission_field", "privilege_flag"}
        for item in parameters
    ):
        candidates.append(
            check(
                "caller has role permission for action", "Broken Function Level Authorization", 0.78
            )
        )
    if any(item.get("semantic_class") == "money_field" for item in parameters):
        candidates.append(
            check(
                "business-critical prices, coupons, discounts, credits, "
                "and balances are calculated server-side",
                "business logic / price tampering",
                0.72,
            )
        )
    if endpoint.get("side_effect") is True:
        candidates.append(
            check(
                "state-changing request is CSRF/replay/business-rule safe",
                "business logic / state flaw",
                0.58,
            )
        )
    for diff in schema_diffs:
        if diff.get("mass_assignment_candidates"):
            candidates.append(
                check(
                    "write body is restricted to an explicit allowlist",
                    "mass assignment",
                    0.82,
                    fields=diff.get("mass_assignment_candidates"),
                )
            )
        if diff.get("excessive_data_candidates"):
            candidates.append(
                check(
                    "response serializer excludes fields not needed by caller/UI",
                    "excessive data exposure",
                    0.76,
                    fields=diff.get("excessive_data_candidates"),
                )
            )
    return dedupe_by_check(candidates)


def check(check_text: str, risk: str, confidence: float, **extra: Any) -> dict[str, Any]:
    item = {"check": check_text, "risk": risk, "confidence": confidence}
    item.update(extra)
    return item


def hypothesis_confidence(
    endpoint: dict[str, Any],
    parameters: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    graph_edges: list[dict[str, Any]],
) -> float:
    confidence = 0.45
    if endpoint.get("source"):
        confidence += 0.08
    if parameters:
        confidence += 0.14
    if schema_diffs:
        confidence += 0.12
    if graph_edges:
        confidence += 0.08
    if endpoint.get("auth_required") is True:
        confidence += 0.05
    return round(min(confidence, 0.9), 2)


def classifications_by_endpoint(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        endpoint_id = str(record.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        output.setdefault(endpoint_id, []).extend(
            parameter for parameter in record.get("parameters") or [] if isinstance(parameter, dict)
        )
    return output


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def dedupe_by_check(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in values:
        key = str(item.get("check") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output
