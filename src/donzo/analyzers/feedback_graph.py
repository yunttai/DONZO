from __future__ import annotations

from typing import Any

from donzo.models import stable_id
from donzo.traffic.redactor import redact_value

SECURE_DENIAL_STATUSES = {401, 403, 404}
VALIDATION_STATUSES = {400, 409, 422}
RATE_LIMIT_STATUSES = {429}
SUCCESS_STATUSES = {200, 201, 204}


def build_feedback_graph(
    manual_feedback: list[dict[str, Any]],
    *,
    dependency_graph: dict[str, Any] | None = None,
    state_transitions: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sanitized = [sanitize_feedback(item) for item in manual_feedback]
    nodes = build_feedback_nodes(sanitized)
    edges = build_feedback_edges(sanitized, dependency_graph or {}, state_transitions or [])
    updates = build_oracle_confidence_updates(sanitized)
    graph = {
        "feedback_graph_id": stable_id(
            "feedback_graph", [item.get("feedback_id") for item in sanitized]
        ),
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "feedback_count": len(sanitized),
            "endpoint_count": len(nodes),
            "edge_count": len(edges),
            "secure_denials": sum(
                1 for item in sanitized if status_bucket(item.get("status")) == "secure_denial"
            ),
            "unexpected_successes": sum(
                1 for item in sanitized if status_bucket(item.get("status")) == "unexpected_success"
            ),
        },
        "policy": {
            "manual_only": True,
            "unsafe_live_exploitation": False,
            "redacted": True,
        },
    }
    return graph, updates


def sanitize_feedback(record: dict[str, Any]) -> dict[str, Any]:
    endpoint_id = str(record.get("endpoint_id") or record.get("test_id") or "unknown")
    status = as_int(
        record.get("status") or record.get("observed_status") or record.get("mutated_status")
    )
    result = {
        "feedback_id": str(
            record.get("feedback_id")
            or stable_id("manual_feedback", endpoint_id, status, record.get("state"))
        ),
        "endpoint_id": endpoint_id,
        "test_id": record.get("test_id"),
        "actor": record.get("actor"),
        "state": record.get("state"),
        "status": status,
        "body_observation": redact_value(
            record.get("body_observation") or record.get("body") or {}
        ),
        "state_observation": redact_value(record.get("state_observation") or {}),
        "read_back_observation": redact_value(
            record.get("read_back_observation") or record.get("read_back") or {}
        ),
        "notes": redact_value(str(record.get("notes") or "")),
        "evidence": [
            str(item) for item in record.get("evidence") or record.get("evidence_files") or []
        ],
        "feedback_bucket": status_bucket(status),
    }
    return compact_empty(result)


def build_feedback_nodes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(str(record.get("endpoint_id") or "unknown"), []).append(record)
    nodes = []
    for endpoint_id, items in grouped.items():
        buckets: dict[str, int] = {}
        for item in items:
            bucket = str(item.get("feedback_bucket") or "unknown")
            buckets[bucket] = buckets.get(bucket, 0) + 1
        nodes.append(
            {
                "node_id": endpoint_id,
                "endpoint_id": endpoint_id,
                "feedback_count": len(items),
                "status_buckets": buckets,
                "precondition_hint": precondition_hint(items),
                "oracle_confidence_hint": oracle_confidence_hint(items),
            }
        )
    return nodes


def build_feedback_edges(
    records: list[dict[str, Any]],
    dependency_graph: dict[str, Any],
    state_transitions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    endpoints = {str(record.get("endpoint_id") or "") for record in records}
    edges: list[dict[str, Any]] = []
    for edge in dependency_graph.get("edges") or []:
        if edge.get("from") in endpoints or edge.get("to") in endpoints:
            edges.append(
                {
                    "edge_id": stable_id("feedback_dependency_edge", edge.get("edge_id")),
                    "source": edge.get("from"),
                    "target": edge.get("to"),
                    "edge_type": "dependency_feedback",
                    "source_edge_id": edge.get("edge_id"),
                    "confidence_delta": 0.08,
                }
            )
    for transition in state_transitions:
        if (
            transition.get("from_endpoint") in endpoints
            or transition.get("to_endpoint") in endpoints
        ):
            edges.append(
                {
                    "edge_id": stable_id("feedback_state_edge", transition.get("transition_id")),
                    "source": transition.get("from_endpoint"),
                    "target": transition.get("to_endpoint"),
                    "edge_type": "state_feedback",
                    "source_transition_id": transition.get("transition_id"),
                    "confidence_delta": 0.08,
                }
            )
    return edges


def build_oracle_confidence_updates(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    for record in records:
        bucket = str(record.get("feedback_bucket") or "unknown")
        delta = {
            "secure_denial": 0.1,
            "validation_rejected": 0.08,
            "rate_limited": 0.03,
            "unexpected_success": 0.2,
            "no_content_success": 0.08,
        }.get(bucket, 0.0)
        updates.append(
            {
                "oracle_confidence_update_id": stable_id(
                    "oracle_confidence_update", record.get("feedback_id"), bucket
                ),
                "feedback_id": record.get("feedback_id"),
                "endpoint_id": record.get("endpoint_id"),
                "status": record.get("status"),
                "feedback_bucket": bucket,
                "confidence_delta": delta,
                "interpretation": interpretation_for_bucket(bucket),
                "manual_review_required": True,
            }
        )
    return updates


def status_bucket(status: Any) -> str:
    value = as_int(status)
    if value in SECURE_DENIAL_STATUSES:
        return "secure_denial"
    if value in VALIDATION_STATUSES:
        return "validation_rejected"
    if value in RATE_LIMIT_STATUSES:
        return "rate_limited"
    if value in {200, 201}:
        return "unexpected_success"
    if value == 204:
        return "no_content_success"
    return "unknown"


def precondition_hint(items: list[dict[str, Any]]) -> str:
    buckets = {str(item.get("feedback_bucket") or "") for item in items}
    if "secure_denial" in buckets:
        return "authorization precondition appears enforced for the tested case"
    if "validation_rejected" in buckets:
        return "input or state precondition appears enforced for the tested case"
    if "unexpected_success" in buckets:
        return "manual review should check whether success changed protected state"
    return "more manual evidence required"


def oracle_confidence_hint(items: list[dict[str, Any]]) -> str:
    buckets = {str(item.get("feedback_bucket") or "") for item in items}
    if "unexpected_success" in buckets:
        return "raise oracle confidence if read-back confirms unauthorized state or data"
    if buckets & {"secure_denial", "validation_rejected"}:
        return "raise expected-behavior confidence for this mutation"
    return "neutral"


def interpretation_for_bucket(bucket: str) -> str:
    return {
        "secure_denial": "denied as expected for authorization mutation",
        "validation_rejected": "rejected by validation or state precondition",
        "rate_limited": "rate limiting observed; do not increase traffic",
        "unexpected_success": "success requires read-back and state review",
        "no_content_success": "success with no body requires state/read-back review",
    }.get(bucket, "unclassified manual feedback")


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compact_empty(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}
