from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from donzo.analyzers.api_model import endpoint_origin
from donzo.analyzers.parameter_classifier import classify_parameter
from donzo.models import stable_id
from donzo.traffic.redactor import redact_value

OPERATION_RE = re.compile(
    r"\b(?P<type>query|mutation|subscription)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)?",
    re.I,
)
FIELD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|\{)")
VARIABLE_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
GRAPHQL_META_FIELDS = {"query", "mutation", "subscription", "fragment", "on"}


def build_graphql_operation_models(traffic: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for record in traffic:
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        body = request.get("body_sample_redacted")
        if not isinstance(body, dict):
            continue
        query = str(body.get("query") or "")
        if not query:
            continue
        url = str(request.get("url") or "")
        if not is_graphql_url_or_body(url, body):
            continue
        operation_name = str(body.get("operationName") or "") or operation_name_from_query(query)
        operation_type = operation_type_from_query(query)
        variables = body.get("variables") if isinstance(body.get("variables"), dict) else {}
        fields = selected_fields(query)
        resource, action = resolver_semantics(operation_type, operation_name, fields)
        parsed = urlparse(url)
        operation_id = stable_id(
            "graphql_operation",
            url,
            operation_name,
            operation_type,
            sorted(variables.keys()),
            record.get("traffic_id"),
        )
        endpoint_name = operation_name or operation_id[:8]
        logical_endpoint_id = (
            f"GRAPHQL {endpoint_origin(url)}{parsed.path or '/graphql'}#{endpoint_name}"
        )
        operations.append(
            compact_empty(
                {
                    "graphql_operation_id": operation_id,
                    "logical_endpoint_id": logical_endpoint_id,
                    "traffic_id": record.get("traffic_id"),
                    "url": url,
                    "origin": endpoint_origin(url),
                    "path": parsed.path or "/graphql",
                    "operation_name": operation_name or "anonymous_operation",
                    "operation_type": operation_type,
                    "variables": redact_value(variables),
                    "variable_names": sorted(str(key) for key in variables),
                    "fields": fields,
                    "node_edge_ids": node_edge_fields(fields, variables),
                    "resource": resource,
                    "action": action,
                    "actor": record.get("actor"),
                    "role": record.get("role"),
                    "tenant": record.get("tenant"),
                    "state": record.get("state"),
                    "flow": record.get("flow"),
                    "label": record.get("label"),
                    "resolver_semantics": {
                        "resource": resource,
                        "action": action,
                        "side_effect": operation_type in {"mutation", "subscription"},
                    },
                    "risk_tags": graphql_risk_tags(operation_type, fields, variables),
                    "evidence": [f"traffic:{record.get('traffic_id')}"],
                    "confidence": 0.86,
                }
            )
        )
    return dedupe_operations(operations)


def build_graphql_logical_endpoint_models(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for operation in operations:
        endpoint_id = str(operation.get("logical_endpoint_id") or "")
        if not endpoint_id:
            continue
        operation_type = str(operation.get("operation_type") or "query")
        method = (
            "QUERY"
            if operation_type == "query"
            else "MUTATION"
            if operation_type == "mutation"
            else "SUBSCRIPTION"
        )
        item = {
            "endpoint_id": endpoint_id,
            "method": method,
            "origin": operation.get("origin"),
            "scheme": urlparse(str(operation.get("url") or "")).scheme,
            "host": urlparse(str(operation.get("url") or "")).netloc,
            "raw_path": operation.get("path") or "/graphql",
            "raw_paths": [operation.get("path") or "/graphql"],
            "path_template": graphql_path_template(operation),
            "observed_urls": [operation.get("url")],
            "source": ["graphql_traffic"],
            "source_evidence": [
                {
                    "source": "graphql_traffic",
                    "traffic_id": operation.get("traffic_id"),
                    "actor": operation.get("actor"),
                    "role": operation.get("role"),
                    "tenant": operation.get("tenant"),
                    "state": operation.get("state"),
                    "flow": operation.get("flow"),
                    "label": operation.get("label"),
                }
            ],
            "confidence": operation.get("confidence", 0.8),
            "auth_required": bool(operation.get("actor") not in {"", None, "anonymous"}),
            "resource": operation.get("resource"),
            "action": operation.get("action"),
            "operation_type": "read" if operation_type == "query" else "mutate",
            "side_effect": operation_type != "query",
            "path_params": [],
            "query_params": [],
            "body_params": operation.get("variable_names") or [],
            "status_codes": [],
            "semantic_tags": ["graphql_operation"],
            "risk_tags": operation.get("risk_tags") or [],
            "related_artifacts": {
                "graphql_operation_id": operation.get("graphql_operation_id"),
                "traffic_id": operation.get("traffic_id"),
            },
        }
        output.append(compact_empty(item))
    return output


def build_graphql_parameter_classifications(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for operation in operations:
        endpoint_id = str(operation.get("logical_endpoint_id") or "")
        parameters = [
            classify_parameter(endpoint_id, str(name), "body", path=f"variables.{name}")
            for name in operation.get("variable_names") or []
        ]
        if not parameters:
            continue
        records.append(
            {
                "classification_id": stable_id("graphql_parameter_classification", endpoint_id),
                "endpoint_id": endpoint_id,
                "method": operation.get("operation_type"),
                "path_template": graphql_path_template(operation),
                "parameters": parameters,
                "risk_tags": sorted(
                    {tag for item in parameters for tag in item.get("risk_tags") or []}
                ),
                "confidence": 0.8,
                "source": "graphql_operation_model",
            }
        )
    return records


def is_graphql_url_or_body(url: str, body: dict[str, Any]) -> bool:
    return "graphql" in url.lower() or "operationName" in body or "variables" in body


def operation_type_from_query(query: str) -> str:
    match = OPERATION_RE.search(query or "")
    if not match:
        return "query"
    return str(match.group("type") or "query").lower()


def operation_name_from_query(query: str) -> str:
    match = OPERATION_RE.search(query or "")
    if not match:
        return ""
    return str(match.group("name") or "")


def selected_fields(query: str) -> list[str]:
    fields = []
    for match in FIELD_RE.finditer(strip_graphql_strings(query)):
        name = match.group(1)
        if name in GRAPHQL_META_FIELDS:
            continue
        fields.append(name)
    return sorted(dict.fromkeys(fields))[:100]


def node_edge_fields(fields: list[str], variables: dict[str, Any]) -> list[str]:
    output = [
        field
        for field in fields
        if field.lower() in {"id", "node", "nodes", "edge", "edges"} or field.lower().endswith("id")
    ]
    output.extend(str(key) for key in variables if str(key).lower().endswith("id"))
    return sorted(dict.fromkeys(output))


def graphql_path_template(operation: dict[str, Any]) -> str:
    return f"{operation.get('path') or '/graphql'}#{operation.get('operation_name')}"


def resolver_semantics(
    operation_type: str, operation_name: str, fields: list[str]
) -> tuple[str, str]:
    name = operation_name or (fields[0] if fields else "graphql")
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    action = "read" if operation_type == "query" else "mutate"
    for marker, value in {
        "create": "create",
        "update": "update",
        "delete": "delete",
        "invite": "invite",
        "approve": "approve",
        "refund": "refund",
        "checkout": "checkout",
        "login": "authenticate",
        "reset": "reset",
    }.items():
        if marker in normalized:
            action = value
            break
    resource = (
        re.sub(
            r"^(get|list|create|update|delete|invite|approve|refund|checkout|reset|send)_?",
            "",
            normalized,
        ).strip("_")
        or "graphql"
    )
    return resource, action


def graphql_risk_tags(
    operation_type: str, fields: list[str], variables: dict[str, Any]
) -> list[str]:
    text = " ".join(fields + list(variables.keys())).lower()
    tags = {"GRAPHQL_OPERATION"}
    if operation_type != "query":
        tags.add("STATE_CHANGING_OPERATION")
    if any(marker in text for marker in ("user", "member", "account", "profile")):
        tags.add("BOLA")
    if any(marker in text for marker in ("org", "tenant", "workspace", "team")):
        tags.add("TENANT_ISOLATION")
    if any(marker in text for marker in ("role", "permission", "admin", "owner")):
        tags.add("BFLA")
    if any(marker in text for marker in ("token", "code", "reset", "invite")):
        tags.add("TOKEN_REPLAY")
    return sorted(tags)


def strip_graphql_strings(query: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', query or "")


def dedupe_operations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        key = str(record.get("graphql_operation_id") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


def compact_empty(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}
