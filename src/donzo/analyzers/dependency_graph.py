from __future__ import annotations

from typing import Any

from donzo.models import stable_id

IDENTIFIER_CLASSES = {"object_identifier", "tenant_identifier", "user_identifier", "token_field"}


def build_api_dependency_graph(
    api_endpoint_models: list[dict[str, Any]],
    *,
    traffic: list[dict[str, Any]] | None = None,
    parameter_classifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    classification_index = classifications_by_endpoint(parameter_classifications or [])
    nodes = [
        build_node(endpoint, classification_index.get(str(endpoint.get("endpoint_id") or ""), []))
        for endpoint in api_endpoint_models
    ]
    edges = build_edges(api_endpoint_models, classification_index, traffic or [])
    return {
        "graph_id": stable_id("api_dependency_graph", len(nodes), len(edges)),
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "producer_consumer_edges": sum(
                1 for edge in edges if edge.get("dependency_type") == "producer_consumer"
            ),
            "sequence_edges": sum(
                1 for edge in edges if edge.get("dependency_type") == "observed_sequence"
            ),
        },
    }


def build_api_sequences(
    traffic: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    model_index = {
        (
            str(item.get("method") or "").upper(),
            str(item.get("origin") or ""),
            str(item.get("path_template") or ""),
        ): item
        for item in api_endpoint_models
    }
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for order, record in enumerate(traffic, start=1):
        actor = str(record.get("actor") or "unknown")
        state = str(record.get("state") or "unknown")
        role = str(record.get("role") or "")
        tenant = str(record.get("tenant") or "")
        flow = str(record.get("flow") or "")
        label = str(record.get("label") or "")
        source_file = str(record.get("source_file") or record.get("source") or "traffic")
        grouped.setdefault((actor, state, source_file, flow), []).append(
            {
                "order": order,
                "record": record,
                "role": role,
                "tenant": tenant,
                "label": label,
            }
        )

    sequences: list[dict[str, Any]] = []
    for (actor, state, source_file, flow), items in grouped.items():
        steps: list[dict[str, Any]] = []
        roles = sorted({str(item.get("role") or "") for item in items if item.get("role")})
        tenants = sorted({str(item.get("tenant") or "") for item in items if item.get("tenant")})
        labels = sorted({str(item.get("label") or "") for item in items if item.get("label")})
        for local_index, item in enumerate(items, start=1):
            record = item["record"]
            request = record.get("request") if isinstance(record.get("request"), dict) else {}
            response = record.get("response") if isinstance(record.get("response"), dict) else {}
            method = str(request.get("method") or "GET").upper()
            url = str(request.get("url") or "")
            model = model_for_url(method, url, model_index)
            steps.append(
                {
                    "step": local_index,
                    "traffic_id": record.get("traffic_id"),
                    "endpoint_id": model.get("endpoint_id") if model else "",
                    "method": method,
                    "url": url,
                    "status": response.get("status"),
                    "action": model.get("action") if model else "",
                    "resource": model.get("resource") if model else "",
                    "flow": record.get("flow"),
                    "label": record.get("label"),
                }
            )
        if not steps:
            continue
        sequences.append(
            {
                "sequence_id": stable_id(
                    "api_sequence",
                    actor,
                    state,
                    source_file,
                    flow,
                    [step.get("endpoint_id") for step in steps],
                ),
                "actor": actor,
                "role": roles[0] if roles else "",
                "tenant": tenants[0] if tenants else "",
                "state": state,
                "flow": flow,
                "labels": labels,
                "source_file": source_file,
                "steps": steps,
                "confidence": 0.9 if len(steps) > 1 else 0.55,
            }
        )
    return sequences


def build_state_transitions(api_sequences: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for sequence in api_sequences:
        steps = [step for step in sequence.get("steps") or [] if isinstance(step, dict)]
        for before, after in zip(steps, steps[1:], strict=False):
            before_action = str(before.get("action") or "").lower()
            after_action = str(after.get("action") or "").lower()
            if not before_action or not after_action:
                continue
            output.append(
                {
                    "transition_id": stable_id(
                        "state_transition",
                        sequence.get("sequence_id"),
                        before.get("endpoint_id"),
                        after.get("endpoint_id"),
                    ),
                    "sequence_id": sequence.get("sequence_id"),
                    "from_endpoint": before.get("endpoint_id"),
                    "to_endpoint": after.get("endpoint_id"),
                    "from_action": before_action,
                    "to_action": after_action,
                    "actor": sequence.get("actor"),
                    "role": sequence.get("role"),
                    "tenant": sequence.get("tenant"),
                    "state": sequence.get("state"),
                    "flow": sequence.get("flow"),
                    "invariant_hints": state_invariant_hints(before_action, after_action),
                    "confidence": 0.65,
                }
            )
    return dedupe_by_id(output, "transition_id")


def build_node(endpoint: dict[str, Any], parameters: list[dict[str, Any]]) -> dict[str, Any]:
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    produces = [
        {
            "field": parameter.get("name"),
            "source": "response.body",
            "semantic_class": parameter.get("semantic_class"),
        }
        for parameter in parameters
        if parameter.get("location") == "response"
        and parameter.get("semantic_class") in IDENTIFIER_CLASSES
    ]
    consumes = [
        {
            "field": parameter.get("name"),
            "location": parameter.get("location"),
            "semantic_class": parameter.get("semantic_class"),
        }
        for parameter in parameters
        if parameter.get("location") in {"path", "query", "body"}
        and parameter.get("semantic_class") in IDENTIFIER_CLASSES
    ]
    return {
        "node_id": endpoint_id,
        "endpoint_id": endpoint_id,
        "operation": endpoint.get("operation_type") or endpoint.get("action"),
        "resource": endpoint.get("resource"),
        "produces": produces,
        "consumes": consumes,
        "confidence": endpoint.get("confidence", 0.0),
    }


def build_edges(
    api_endpoint_models: list[dict[str, Any]],
    classification_index: dict[str, list[dict[str, Any]]],
    traffic: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for producer in api_endpoint_models:
        producer_id = str(producer.get("endpoint_id") or "")
        produced = [
            item
            for item in classification_index.get(producer_id, [])
            if item.get("location") == "response"
            and item.get("semantic_class") in IDENTIFIER_CLASSES
        ]
        if not produced:
            continue
        for consumer in api_endpoint_models:
            consumer_id = str(consumer.get("endpoint_id") or "")
            if producer_id == consumer_id:
                continue
            if (
                producer.get("origin")
                and consumer.get("origin")
                and producer.get("origin") != consumer.get("origin")
            ):
                continue
            consumed = [
                item
                for item in classification_index.get(consumer_id, [])
                if item.get("location") in {"path", "query", "body"}
                and item.get("semantic_class") in IDENTIFIER_CLASSES
            ]
            for produced_field in produced:
                for consumed_field in consumed:
                    confidence, evidence = dependency_match_confidence(
                        producer, consumer, produced_field, consumed_field
                    )
                    if confidence < 0.55:
                        continue
                    edges.append(
                        {
                            "edge_id": stable_id(
                                "dependency_edge",
                                producer_id,
                                consumer_id,
                                produced_field.get("name"),
                                consumed_field.get("name"),
                            ),
                            "from": producer_id,
                            "to": consumer_id,
                            "dependency_type": "producer_consumer",
                            "field": consumed_field.get("name"),
                            "produced_field": produced_field.get("name"),
                            "evidence": evidence,
                            "confidence": confidence,
                        }
                    )
    edges.extend(observed_value_edges(traffic, api_endpoint_models))
    edges.extend(observed_sequence_edges(traffic, api_endpoint_models))
    return dedupe_by_id(edges, "edge_id")[:500]


def dependency_match_confidence(
    producer: dict[str, Any],
    consumer: dict[str, Any],
    produced_field: dict[str, Any],
    consumed_field: dict[str, Any],
) -> tuple[float, list[str]]:
    confidence = 0.35
    evidence: list[str] = []
    produced_name = normalize_name(str(produced_field.get("name") or ""))
    consumed_name = normalize_name(str(consumed_field.get("name") or ""))
    if produced_name and consumed_name and produced_name == consumed_name:
        confidence += 0.25
        evidence.append(
            "response field "
            f"{produced_field.get('name')} matched request field "
            f"{consumed_field.get('name')}"
        )
    if produced_name == "id" and consumed_name.endswith("_id"):
        confidence += 0.2
        evidence.append("generic response id matched identifier consumer field")
    if produced_field.get("semantic_class") == consumed_field.get("semantic_class"):
        confidence += 0.12
        evidence.append(f"semantic class matched: {produced_field.get('semantic_class')}")
    if producer.get("resource") and producer.get("resource") == consumer.get("resource"):
        confidence += 0.16
        evidence.append(f"same resource: {producer.get('resource')}")
    elif producer.get("resource") and str(producer.get("resource")) in str(
        consumer.get("path_template") or ""
    ):
        confidence += 0.08
        evidence.append("producer resource appears in consumer path")
    if str(producer.get("operation_type") or "") in {"create", "mutate", "update"}:
        confidence += 0.1
        evidence.append("producer endpoint can create or mutate state")
    return round(min(confidence, 0.95), 2), evidence


def observed_sequence_edges(
    traffic: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sequences = build_api_sequences(traffic, api_endpoint_models)
    edges: list[dict[str, Any]] = []
    for sequence in sequences:
        steps = [step for step in sequence.get("steps") or [] if isinstance(step, dict)]
        for before, after in zip(steps, steps[1:], strict=False):
            if not before.get("endpoint_id") or not after.get("endpoint_id"):
                continue
            edges.append(
                {
                    "edge_id": stable_id(
                        "sequence_edge",
                        sequence.get("sequence_id"),
                        before.get("endpoint_id"),
                        after.get("endpoint_id"),
                    ),
                    "from": before.get("endpoint_id"),
                    "to": after.get("endpoint_id"),
                    "dependency_type": "observed_sequence",
                    "evidence": [
                        f"observed step {before.get('step')} before "
                        f"step {after.get('step')} in same HAR actor/state"
                    ],
                    "confidence": 0.62,
                }
            )
    return edges


def observed_value_edges(
    traffic: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    model_index = {
        (
            str(item.get("method") or "").upper(),
            str(item.get("origin") or ""),
            str(item.get("path_template") or ""),
        ): item
        for item in api_endpoint_models
    }
    ordered = sorted(
        traffic,
        key=lambda item: (
            str(item.get("source_file") or ""),
            int(item.get("sequence_index") or 0),
        ),
    )
    edges: list[dict[str, Any]] = []
    for index, producer_record in enumerate(ordered):
        producer_model = model_from_record(producer_record, model_index)
        if not producer_model:
            continue
        producer_values = response_identifier_values(producer_record)
        if not producer_values:
            continue
        for consumer_record in ordered[index + 1 :]:
            if producer_record.get("actor") != consumer_record.get("actor"):
                continue
            consumer_model = model_from_record(consumer_record, model_index)
            if not consumer_model:
                continue
            consumer_values = request_observed_values(consumer_record)
            for produced_field, produced_value in producer_values:
                if produced_value not in consumer_values:
                    continue
                edges.append(
                    {
                        "edge_id": stable_id(
                            "value_dependency_edge",
                            producer_model.get("endpoint_id"),
                            consumer_model.get("endpoint_id"),
                            produced_field,
                            produced_value,
                        ),
                        "from": producer_model.get("endpoint_id"),
                        "to": consumer_model.get("endpoint_id"),
                        "dependency_type": "producer_consumer",
                        "field": produced_field,
                        "produced_field": produced_field,
                        "evidence": [
                            f"redacted response field {produced_field} "
                            "value appeared in later request",
                            "same actor and observed HAR order",
                        ],
                        "confidence": 0.94,
                    }
                )
    return edges


def model_from_record(
    record: dict[str, Any],
    model_index: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    method = str(request.get("method") or "GET").upper()
    url = str(request.get("url") or "")
    return model_for_url(method, url, model_index)


def response_identifier_values(record: dict[str, Any]) -> list[tuple[str, str]]:
    response = record.get("response") if isinstance(record.get("response"), dict) else {}
    body = response.get("body_sample_redacted")
    values: list[tuple[str, str]] = []
    for path, value in walk_primitives(body):
        name = path.split(".")[-1]
        normalized = normalize_name(name)
        if normalized in {"id", "uuid"} or normalized.endswith("_id") or "token" in normalized:
            text = str(value)
            if text and not text.startswith("[") and len(text) <= 128:
                values.append((name, text))
    return values


def request_observed_values(record: dict[str, Any]) -> set[str]:
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    values: set[str] = set()
    url = str(request.get("url") or "")
    if url:
        values.update(
            part
            for part in url.replace("?", "/").replace("&", "/").replace("=", "/").split("/")
            if part
        )
    for _path, value in walk_primitives(request.get("query")):
        values.add(str(value))
    for _path, value in walk_primitives(request.get("body_sample_redacted")):
        values.add(str(value))
    return {value for value in values if value and not value.startswith("[")}


def walk_primitives(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        output: list[tuple[str, Any]] = []
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            output.extend(walk_primitives(item, path))
        return output
    if isinstance(value, list):
        output: list[tuple[str, Any]] = []
        for index, item in enumerate(value[:20]):
            path = f"{prefix}[{index}]"
            output.extend(walk_primitives(item, path))
        return output
    if value is None or isinstance(value, (dict, list)):
        return []
    return [(prefix, value)]


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


def model_for_url(
    method: str,
    url: str,
    model_index: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    from urllib.parse import urlparse

    from donzo.analyzers.api_model import endpoint_origin, template_path

    parsed = urlparse(url)
    return model_index.get((method, endpoint_origin(url), template_path(parsed.path or "/")))


def state_invariant_hints(before_action: str, after_action: str) -> list[str]:
    hints: list[str] = []
    if before_action in {"create", "submit", "invite"}:
        hints.append("created object should be usable only by authorized actors")
    if after_action in {"approve", "reject", "delete", "archive"}:
        hints.append("state-changing action should require role and current-state checks")
    if before_action == after_action:
        hints.append("replayed state transition should be idempotent or rejected when appropriate")
    return hints


def normalize_name(value: str) -> str:
    import re

    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9_]+", "_", spaced.lower()).strip("_")


def dedupe_by_id(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        value = str(record.get(key) or "")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(record)
    return output
