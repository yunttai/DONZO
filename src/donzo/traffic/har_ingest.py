from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from donzo.analyzers.schema_infer import infer_schema, infer_schema_fields
from donzo.config import ScopeConfig
from donzo.models import stable_id
from donzo.traffic.redactor import has_auth_material, redact_headers, redact_value


def ingest_har_files(
    paths: list[Path],
    *,
    config: ScopeConfig,
    actor: str = "unknown",
    role: str = "",
    tenant: str = "",
    state: str = "unknown",
    flow: str = "",
    label: str = "",
    source: str = "har",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    traffic: list[dict[str, Any]] = []
    request_schemas: list[dict[str, Any]] = []
    response_schemas: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for path in paths:
        file_traffic, file_requests, file_responses, file_removed = ingest_har_file(
            path,
            config=config,
            actor=actor,
            role=role,
            tenant=tenant,
            state=state,
            flow=flow,
            label=label,
            source=source,
        )
        traffic.extend(file_traffic)
        request_schemas.extend(file_requests)
        response_schemas.extend(file_responses)
        removed.extend(file_removed)
    return (
        dedupe_by_id(traffic, "traffic_id"),
        dedupe_by_id(request_schemas, "schema_id"),
        dedupe_by_id(response_schemas, "schema_id"),
        removed,
    )


def ingest_har_file(
    path: Path,
    *,
    config: ScopeConfig,
    actor: str = "unknown",
    role: str = "",
    tenant: str = "",
    state: str = "unknown",
    flow: str = "",
    label: str = "",
    source: str = "har",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = har_entries(document)
    traffic: list[dict[str, Any]] = []
    request_schemas: list[dict[str, Any]] = []
    response_schemas: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        url = str(request.get("url") or "")
        if not url:
            removed.append({"record": f"{path}:{index}", "reason": "missing request url"})
            continue
        decision = config.scope.decide(url)
        if not decision.allowed:
            removed.append({"record": url, "reason": "; ".join(decision.reasons)})
            continue
        method = str(request.get("method") or "GET").upper()
        parsed = urlparse(url)
        request_headers_raw = headers_to_dict(request.get("headers"))
        response_headers_raw = headers_to_dict(response.get("headers"))
        request_body = parse_request_body(request)
        response_body = parse_response_body(response)
        traffic_id = stable_id(
            "traffic", path, index, actor, role, tenant, state, flow, label, method, url
        )
        endpoint_id = stable_id(
            "endpoint_observed", method, parsed.path, sorted(parse_qs(parsed.query))
        )
        request_schema = infer_schema(request_body) if request_body is not None else None
        response_schema = infer_schema(response_body) if response_body is not None else None
        traffic_record = {
            "traffic_id": traffic_id,
            "endpoint_observation_id": endpoint_id,
            "actor": actor,
            "role": role,
            "tenant": tenant,
            "state": state,
            "flow": flow,
            "label": label,
            "sequence_index": index,
            "source": source,
            "source_file": str(path),
            "request": {
                "method": method,
                "url": url,
                "path": parsed.path or "/",
                "headers": redact_headers(request_headers_raw),
                "auth_present": has_auth_material(request_headers_raw),
                "query": redact_value(flatten_query(parse_qs(parsed.query))),
                "body_schema": request_schema,
                "body_sample_redacted": redact_value(request_body),
            },
            "response": {
                "status": as_int(response.get("status")),
                "headers": redact_headers(response_headers_raw),
                "content_type": response_content_type(response, response_headers_raw),
                "body_schema": response_schema,
                "body_sample_redacted": redact_value(response_body),
            },
        }
        traffic.append(compact_empty(traffic_record))
        if request_body is not None:
            request_schemas.append(
                schema_record(
                    schema_id=stable_id("request_schema", method, parsed.path, request_schema),
                    endpoint_observation_id=endpoint_id,
                    method=method,
                    url=url,
                    schema_kind="request",
                    content_type=request_content_type(request, request_headers_raw),
                    schema=request_schema,
                    fields=infer_schema_fields(request_body),
                    actor=actor,
                    role=role,
                    tenant=tenant,
                    state=state,
                    flow=flow,
                    label=label,
                    source=source,
                )
            )
        if response_body is not None:
            response_schemas.append(
                schema_record(
                    schema_id=stable_id("response_schema", method, parsed.path, response_schema),
                    endpoint_observation_id=endpoint_id,
                    method=method,
                    url=url,
                    schema_kind="response",
                    content_type=response_content_type(response, response_headers_raw),
                    status=as_int(response.get("status")),
                    schema=response_schema,
                    fields=infer_schema_fields(response_body),
                    actor=actor,
                    role=role,
                    tenant=tenant,
                    state=state,
                    flow=flow,
                    label=label,
                    source=source,
                )
            )
    return traffic, request_schemas, response_schemas, removed


def endpoint_records_from_traffic(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for record in records:
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        url = str(request.get("url") or "")
        if not url:
            continue
        endpoints.append(
            {
                "url": url,
                "method": str(request.get("method") or "GET").upper(),
                "status_code": response.get("status"),
                "content_type": response.get("content_type"),
                "params": sorted((request.get("query") or {}).keys())
                if isinstance(request.get("query"), dict)
                else [],
                "requires_auth_guess": request.get("auth_present") is True,
                "request_body_fields": schema_field_names(request.get("body_schema")),
                "response_fields": schema_field_names(response.get("body_schema")),
                "source_context": {
                    "traffic_id": record.get("traffic_id"),
                    "actor": record.get("actor"),
                    "role": record.get("role"),
                    "tenant": record.get("tenant"),
                    "state": record.get("state"),
                    "flow": record.get("flow"),
                    "label": record.get("label"),
                    "source_file": record.get("source_file"),
                },
            }
        )
    return endpoints


def har_entries(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict):
        log = document.get("log")
        if isinstance(log, dict) and isinstance(log.get("entries"), list):
            return [entry for entry in log["entries"] if isinstance(entry, dict)]
        if isinstance(document.get("entries"), list):
            return [entry for entry in document["entries"] if isinstance(entry, dict)]
    if isinstance(document, list):
        return [entry for entry in document if isinstance(entry, dict)]
    return []


def headers_to_dict(headers: Any) -> dict[str, str]:
    if isinstance(headers, list):
        output: dict[str, str] = {}
        for item in headers:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            output[name] = str(item.get("value") or "")
        return output
    if isinstance(headers, dict):
        return {str(key): str(value) for key, value in headers.items()}
    return {}


def parse_request_body(request: dict[str, Any]) -> Any:
    post_data = request.get("postData")
    if not isinstance(post_data, dict):
        return None
    text = str(post_data.get("text") or "")
    mime_type = str(post_data.get("mimeType") or "")
    if text:
        return parse_body_text(text, mime_type)
    params = post_data.get("params")
    if isinstance(params, list):
        return {
            str(item.get("name") or ""): str(item.get("value") or "")
            for item in params
            if isinstance(item, dict) and str(item.get("name") or "")
        }
    return None


def parse_response_body(response: dict[str, Any]) -> Any:
    content = response.get("content")
    if not isinstance(content, dict):
        return None
    text = str(content.get("text") or "")
    if not text:
        return None
    encoding = str(content.get("encoding") or "").lower()
    if encoding == "base64":
        try:
            text = base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, OSError):
            return None
    return parse_body_text(text, str(content.get("mimeType") or ""))


def parse_body_text(text: str, mime_type: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return None
    lowered_type = mime_type.lower()
    if "json" in lowered_type or stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return None
    if "x-www-form-urlencoded" in lowered_type:
        return flatten_query(parse_qs(stripped))
    return None


def schema_record(
    *,
    schema_id: str,
    endpoint_observation_id: str,
    method: str,
    url: str,
    schema_kind: str,
    content_type: str,
    schema: Any,
    fields: list[dict[str, Any]],
    actor: str,
    role: str,
    tenant: str,
    state: str,
    flow: str,
    label: str,
    source: str,
    status: int | None = None,
) -> dict[str, Any]:
    record = {
        "schema_id": schema_id,
        "endpoint_observation_id": endpoint_observation_id,
        "method": method,
        "url": url,
        "schema_kind": schema_kind,
        "content_type": content_type,
        "status": status,
        "schema": schema,
        "fields": fields,
        "actor": actor,
        "role": role,
        "tenant": tenant,
        "state": state,
        "flow": flow,
        "label": label,
        "source": source,
    }
    return compact_empty(record)


def request_content_type(request: dict[str, Any], headers: dict[str, str]) -> str:
    post_data = request.get("postData")
    if isinstance(post_data, dict) and post_data.get("mimeType"):
        return str(post_data.get("mimeType") or "")
    return header_value(headers, "content-type")


def response_content_type(response: dict[str, Any], headers: dict[str, str]) -> str:
    content = response.get("content")
    if isinstance(content, dict) and content.get("mimeType"):
        return str(content.get("mimeType") or "")
    return header_value(headers, "content-type")


def header_value(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return str(value)
    return ""


def flatten_query(values: dict[str, list[str]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, items in values.items():
        if len(items) == 1:
            output[key] = items[0]
        else:
            output[key] = items
    return output


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compact_empty(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}


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


def schema_field_names(schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return []
    return sorted(str(key) for key, value in schema.items() if key != "type" and value is not None)
