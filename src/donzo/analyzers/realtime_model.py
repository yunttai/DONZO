from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from donzo.analyzers.parameter_classifier import classify_parameter
from donzo.analyzers.schema_infer import infer_schema, infer_schema_fields
from donzo.config import ScopeConfig
from donzo.models import stable_id
from donzo.traffic.redactor import has_auth_material, redact_headers, redact_value


def build_websocket_message_models(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    messages: list[dict[str, Any]] = []
    logical_endpoints: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        url = str(record.get("connection_url") or record.get("url") or "")
        if config and url and not config.scope.decide(url).allowed:
            removed.append({"record": url, "reason": "out_of_scope"})
            continue
        headers = record.get("headers") if isinstance(record.get("headers"), dict) else {}
        payload = record.get("payload") if "payload" in record else record.get("message")
        payload_redacted = redact_value(payload)
        schema = infer_schema(payload_redacted)
        message_type = str(record.get("message_type") or infer_message_type(payload_redacted))
        ids = realtime_identifier_fields(payload_redacted)
        message_id = stable_id("websocket_message", url, message_type, index, schema)
        message = {
            "websocket_message_id": message_id,
            "connection_url": url,
            "direction": str(record.get("direction") or "unknown"),
            "message_type": message_type,
            "payload_schema": schema,
            "payload_fields": infer_schema_fields(payload_redacted),
            "channel_ids": ids,
            "auth_handshake": {
                "auth_present": has_auth_material(headers),
                "headers": redact_headers(headers),
            },
            "actor": record.get("actor"),
            "role": record.get("role"),
            "tenant": record.get("tenant"),
            "flow": record.get("flow"),
            "risk_tags": realtime_risk_tags(message_type, ids),
            "confidence": 0.72,
        }
        messages.append(compact_empty(message))
        logical_endpoints.append(realtime_logical_endpoint(message, "websocket"))
    return messages, dedupe_by_id(logical_endpoints, "logical_endpoint_id"), removed


def build_sse_event_models(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    logical_endpoints: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        url = str(record.get("stream_url") or record.get("url") or "")
        if config and url and not config.scope.decide(url).allowed:
            removed.append({"record": url, "reason": "out_of_scope"})
            continue
        data = record.get("data") if "data" in record else record.get("payload")
        data_redacted = redact_value(data)
        schema = infer_schema(data_redacted)
        event_name = str(record.get("event_name") or record.get("event") or "message")
        ids = realtime_identifier_fields(data_redacted)
        event_id = stable_id("sse_event", url, event_name, index, schema)
        event = {
            "sse_event_id": event_id,
            "stream_url": url,
            "event_name": event_name,
            "stream_scope": stream_scope(url, ids),
            "response_schema": schema,
            "response_fields": infer_schema_fields(data_redacted),
            "tenant_data_leakage_candidates": leakage_candidates(ids),
            "actor": record.get("actor"),
            "role": record.get("role"),
            "tenant": record.get("tenant"),
            "flow": record.get("flow"),
            "risk_tags": realtime_risk_tags(event_name, ids),
            "confidence": 0.7,
        }
        events.append(compact_empty(event))
        logical_endpoints.append(realtime_logical_endpoint(event, "sse"))
    return events, dedupe_by_id(logical_endpoints, "logical_endpoint_id"), removed


def realtime_logical_endpoint(record: dict[str, Any], protocol: str) -> dict[str, Any]:
    url = str(record.get("connection_url") or record.get("stream_url") or "")
    parsed = urlparse(url)
    name = str(record.get("message_type") or record.get("event_name") or "message")
    endpoint_id = f"{protocol.upper()} {parsed.netloc}{parsed.path}#{name}"
    ids = record.get("channel_ids") or record.get("tenant_data_leakage_candidates") or []
    parameters = [classify_parameter(endpoint_id, str(item), "message") for item in ids]
    return compact_empty(
        {
            "logical_endpoint_id": endpoint_id,
            "protocol": protocol,
            "url": url,
            "message_or_event": name,
            "resource": resource_from_realtime_name(name),
            "action": "subscribe" if protocol == "sse" else "send_or_receive",
            "parameters": parameters,
            "risk_tags": sorted(
                {tag for item in parameters for tag in item.get("risk_tags") or []}
                | set(record.get("risk_tags") or [])
            ),
            "actor": record.get("actor"),
            "role": record.get("role"),
            "tenant": record.get("tenant"),
            "flow": record.get("flow"),
            "confidence": record.get("confidence", 0.7),
        }
    )


def infer_message_type(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("type", "event", "action", "op", "operation"):
            if payload.get(key):
                return str(payload[key])
    return "message"


def realtime_identifier_fields(value: Any, prefix: str = "") -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if (
                lowered == "id"
                or lowered.endswith("id")
                or lowered in {"room", "channel", "tenant", "org", "project"}
            ):
                output.append(path)
            output.extend(realtime_identifier_fields(item, path))
    elif isinstance(value, list):
        for item in value[:20]:
            output.extend(realtime_identifier_fields(item, prefix))
    return sorted(dict.fromkeys(output))[:50]


def realtime_risk_tags(name: str, identifiers: list[str]) -> list[str]:
    text = " ".join([name] + identifiers).lower()
    tags = {"REALTIME"}
    if any(
        marker in text
        for marker in ("tenant", "org", "workspace", "team", "room", "channel", "project")
    ):
        tags.add("TENANT_ISOLATION")
    if any(marker in text for marker in ("user", "member", "owner")):
        tags.add("BOLA")
    return sorted(tags)


def stream_scope(url: str, identifiers: list[str]) -> str:
    parsed = urlparse(url)
    if any("tenant" in item.lower() or "org" in item.lower() for item in identifiers):
        return "tenant_scoped"
    if any("room" in item.lower() or "channel" in item.lower() for item in identifiers):
        return "channel_scoped"
    return parsed.path or "unknown"


def leakage_candidates(identifiers: list[str]) -> list[str]:
    return [
        item
        for item in identifiers
        if any(
            marker in item.lower()
            for marker in ("tenant", "org", "workspace", "team", "user", "member")
        )
    ]


def resource_from_realtime_name(name: str) -> str:
    return str(name or "message").lower().replace(".", "_").replace("-", "_")


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


def compact_empty(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}
