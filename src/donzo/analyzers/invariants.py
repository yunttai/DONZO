from __future__ import annotations

from typing import Any

from donzo.actors import actor_context_for_endpoint
from donzo.models import stable_id


def build_security_invariants(
    api_endpoint_models: list[dict[str, Any]],
    *,
    handler_hypotheses: list[dict[str, Any]] | None = None,
    parameter_classifications: list[dict[str, Any]] | None = None,
    schema_diffs: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, Any] | None = None,
    actor_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    classification_index = classifications_by_endpoint(parameter_classifications or [])
    hypothesis_index = {
        str(item.get("endpoint_id") or ""): item for item in handler_hypotheses or []
    }
    graph_edges = dependency_graph.get("edges") if isinstance(dependency_graph, dict) else []
    output: list[dict[str, Any]] = []
    for endpoint in api_endpoint_models:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        parameters = classification_index.get(endpoint_id, [])
        hypothesis = hypothesis_index.get(endpoint_id, {})
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
        actor_context = actor_context_for_endpoint(endpoint, actor_model)
        endpoint_items = endpoint_invariants(
            endpoint, parameters, hypothesis, related_diffs, related_edges
        )
        if actor_context:
            for item in endpoint_items:
                item["actor_context"] = actor_context
        output.extend(endpoint_items)
    return dedupe_invariants(output)


def endpoint_invariants(
    endpoint: dict[str, Any],
    parameters: list[dict[str, Any]],
    hypothesis: dict[str, Any],
    schema_diffs: list[dict[str, Any]],
    graph_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    invariants: list[dict[str, Any]] = []
    if any(item.get("semantic_class") == "tenant_identifier" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "tenant_isolation",
                "caller must belong to the tenant/workspace/org referenced by the request",
                "high",
                "BOLA",
                0.82,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(item.get("semantic_class") == "object_identifier" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "object_ownership",
                "caller must be authorized for the "
                f"{endpoint.get('resource') or 'object'} identifier",
                "high",
                "BOLA",
                0.8,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(item.get("semantic_class") == "user_identifier" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "user_scope",
                "caller must be self, delegated actor, or privileged admin for referenced user",
                "medium",
                "IDOR / user data exposure",
                0.72,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(
        item.get("semantic_class") in {"role_field", "permission_field", "privilege_flag"}
        for item in parameters
    ):
        invariants.append(
            invariant(
                endpoint_id,
                "role_authorization",
                "caller role must permit the requested function and target role/permission change",
                "critical",
                "BFLA / privilege escalation",
                0.82,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
        invariants.append(
            invariant(
                endpoint_id,
                "function_level_authorization",
                "caller must be authorized to invoke this endpoint's function, "
                "independent of object ownership",
                "high",
                "BFLA",
                0.76,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(item.get("semantic_class") == "money_field" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "server_side_price_calculation",
                "price, amount, coupon, discount, credit, and balance effects "
                "must be calculated or verified server-side",
                "high",
                "business logic flaw",
                0.72,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(item.get("semantic_class") == "quantity_field" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "server_side_quantity_validation",
                "quantity, count, limit, and size fields must be bounded and validated server-side",
                "medium",
                "business logic flaw",
                0.66,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(item.get("semantic_class") == "token_field" for item in parameters):
        invariants.append(
            invariant(
                endpoint_id,
                "token_lifetime",
                "tokens, codes, nonces, and reset/invite secrets must expire "
                "and be scoped to the intended actor/action",
                "high",
                "replay or token misuse",
                0.74,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if (
        any(item.get("semantic_class") == "state_field" for item in parameters)
        or endpoint.get("side_effect") is True
    ):
        invariants.append(
            invariant(
                endpoint_id,
                "state_transition",
                "state-changing operation must enforce current-state, replay, "
                "and authorization checks",
                "medium",
                "business logic flaw",
                0.62,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
    if any(
        item.get("semantic_class")
        in {
            "url_field",
            "callback_field",
            "webhook_field",
            "file_field",
            "path_field",
            "template_field",
        }
        for item in parameters
    ):
        invariants.append(
            invariant(
                endpoint_id,
                "sink_sanitization",
                "sink-like input must be constrained to allowed destinations, "
                "files, paths, or templates",
                "medium",
                "SSRF / open redirect / file access / injection",
                0.68,
                evidence_refs(endpoint, hypothesis, graph_edges),
            )
        )
        if any(
            item.get("semantic_class") in {"callback_field", "webhook_field", "url_field"}
            for item in parameters
        ):
            invariants.append(
                invariant(
                    endpoint_id,
                    "callback_destination_validation",
                    "callback, redirect, webhook, and URL destinations must be "
                    "allowlisted or constrained to safe origins",
                    "medium",
                    "SSRF / open redirect / callback abuse",
                    0.72,
                    evidence_refs(endpoint, hypothesis, graph_edges),
                )
            )
        if any(
            item.get("semantic_class") in {"file_field", "path_field", "filename_field"}
            for item in parameters
        ):
            invariants.append(
                invariant(
                    endpoint_id,
                    "file_path_constraint",
                    "file, filename, and path inputs must remain inside the "
                    "intended storage boundary",
                    "medium",
                    "file access control",
                    0.72,
                    evidence_refs(endpoint, hypothesis, graph_edges),
                )
            )
    for diff in schema_diffs:
        if diff.get("mass_assignment_candidates"):
            invariants.append(
                invariant(
                    endpoint_id,
                    "field_allowlist",
                    "write endpoint must ignore or reject read-only/sensitive "
                    "fields not observed in legitimate write body",
                    "high",
                    "mass assignment",
                    0.84,
                    evidence_refs(endpoint, hypothesis, graph_edges, diff),
                    fields=diff.get("mass_assignment_candidates"),
                )
            )
            invariants.append(
                invariant(
                    endpoint_id,
                    "read_only_field_protection",
                    "read-only fields from response schemas must not be "
                    "client-controlled through write requests",
                    "high",
                    "mass assignment",
                    0.82,
                    evidence_refs(endpoint, hypothesis, graph_edges, diff),
                    fields=diff.get("mass_assignment_candidates"),
                )
            )
        if diff.get("excessive_data_candidates"):
            invariants.append(
                invariant(
                    endpoint_id,
                    "response_field_minimization",
                    "read response must not expose sensitive or privileged "
                    "fields unauthorized for caller/UI",
                    "medium",
                    "excessive data exposure",
                    0.78,
                    evidence_refs(endpoint, hypothesis, graph_edges, diff),
                    fields=diff.get("excessive_data_candidates"),
                )
            )
            invariants.append(
                invariant(
                    endpoint_id,
                    "response_minimization",
                    "read response must not expose sensitive or privileged "
                    "fields unauthorized for caller/UI",
                    "medium",
                    "excessive data exposure",
                    0.76,
                    evidence_refs(endpoint, hypothesis, graph_edges, diff),
                    fields=diff.get("excessive_data_candidates"),
                )
            )
    return invariants


def invariant(
    endpoint_id: str,
    invariant_type: str,
    statement: str,
    severity: str,
    candidate_vulnerability: str,
    confidence: float,
    evidence: list[str],
    **extra: Any,
) -> dict[str, Any]:
    item = {
        "invariant_id": stable_id("security_invariant", endpoint_id, invariant_type, statement),
        "endpoint_id": endpoint_id,
        "type": invariant_type,
        "statement": statement,
        "severity_if_violated": severity,
        "candidate_vulnerability": candidate_vulnerability,
        "confidence": confidence,
        "evidence": evidence,
    }
    item.update(extra)
    return item


def evidence_refs(
    endpoint: dict[str, Any],
    hypothesis: dict[str, Any],
    graph_edges: list[dict[str, Any]],
    schema_diff: dict[str, Any] | None = None,
) -> list[str]:
    evidence = [f"endpoint_model:{endpoint.get('endpoint_id')}"]
    if hypothesis:
        evidence.append(f"handler_hypothesis:{hypothesis.get('hypothesis_id')}")
    if schema_diff:
        evidence.append(f"schema_diff:{schema_diff.get('schema_diff_id')}")
    for edge in graph_edges[:3]:
        evidence.append(f"dependency_edge:{edge.get('edge_id')}")
    return evidence


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


def dedupe_invariants(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        value = str(record.get("invariant_id") or "")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(record)
    return output
