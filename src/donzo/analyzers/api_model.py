from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from donzo.models import stable_id

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def build_api_endpoint_models(
    endpoints: list[dict[str, Any]],
    *,
    traffic: list[dict[str, Any]] | None = None,
    request_schemas: list[dict[str, Any]] | None = None,
    response_schemas: list[dict[str, Any]] | None = None,
    api_semantic_map: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        method = str(endpoint.get("method") or "GET").upper()
        parsed = urlparse(url)
        path_template = template_path(parsed.path or "/")
        key = (method, endpoint_origin(url), path_template)
        model = merged.setdefault(key, base_model(method, url, path_template))
        merge_sources(model, endpoint.get("source") or ["endpoint"])
        model["observed_urls"].add(url)
        model["raw_paths"].add(parsed.path or "/")
        model["source_evidence"].append(
            {
                "source": endpoint.get("source") or ["endpoint"],
                "url": url,
                "status_code": endpoint.get("status_code"),
                "endpoint_id": endpoint.get("endpoint_id"),
            }
        )
        model["query_params"].update(sorted(parse_qs(parsed.query).keys()))
        model["query_params"].update(str(item) for item in endpoint.get("params") or [])
        model["status_codes"].update(
            [endpoint.get("status_code")] if endpoint.get("status_code") else []
        )
        if endpoint.get("requires_auth_guess") is True:
            model["auth_required"] = True
        model["confidence"] = max(
            float(model["confidence"]), source_confidence(endpoint.get("source"))
        )

    for record in traffic or []:
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        url = str(request.get("url") or "")
        if not url:
            continue
        method = str(request.get("method") or "GET").upper()
        parsed = urlparse(url)
        path_template = template_path(parsed.path or "/")
        key = (method, endpoint_origin(url), path_template)
        model = merged.setdefault(key, base_model(method, url, path_template))
        merge_sources(model, [str(record.get("source") or "har")])
        model["observed_urls"].add(url)
        model["raw_paths"].add(parsed.path or "/")
        model["source_evidence"].append(
            {
                "source": record.get("source") or "har",
                "traffic_id": record.get("traffic_id"),
                "actor": record.get("actor"),
                "role": record.get("role"),
                "tenant": record.get("tenant"),
                "state": record.get("state"),
                "flow": record.get("flow"),
                "label": record.get("label"),
                "sequence_index": record.get("sequence_index"),
            }
        )
        model["query_params"].update(str(item) for item in request.get("query") or {})
        status = response.get("status")
        if status is not None:
            model["status_codes"].add(status)
        if request.get("auth_present") is True:
            model["auth_required"] = True
        model["confidence"] = max(float(model["confidence"]), 0.95)

    request_schema_index = schemas_by_endpoint(request_schemas or [])
    response_schema_index = schemas_by_endpoint(response_schemas or [])
    request_field_index = schema_field_names_by_endpoint(request_schemas or [])
    semantic_index = semantic_by_model(api_semantic_map or [])
    output: list[dict[str, Any]] = []
    for key, model in merged.items():
        method, origin, path_template = key
        endpoint_id = endpoint_model_id(method, origin, path_template)
        request_refs = [item.get("schema_id") for item in request_schema_index.get(key, [])]
        response_refs = [item.get("schema_id") for item in response_schema_index.get(key, [])]
        semantic = semantic_index.get(key, {})
        raw_paths = sorted(model["raw_paths"])
        parsed_origin = urlparse(origin if origin else "")
        item = {
            "endpoint_id": endpoint_id,
            "method": method,
            "origin": origin,
            "scheme": parsed_origin.scheme,
            "host": parsed_origin.netloc,
            "raw_path": raw_paths[0] if raw_paths else path_template,
            "raw_paths": raw_paths[:20],
            "path_template": path_template,
            "observed_urls": sorted(model["observed_urls"])[:20],
            "source": sorted(model["source"]),
            "source_evidence": model["source_evidence"][:20],
            "confidence": round(float(model["confidence"]), 2),
            "auth_required": bool(model["auth_required"]),
            "auth_guess": semantic.get("auth_guess"),
            "resource": semantic.get("resource") or resource_from_template(path_template),
            "action": semantic.get("action") or operation_from_method(method),
            "operation_type": operation_type(method, semantic.get("action")),
            "side_effect": method in {"POST", "PUT", "PATCH", "DELETE"},
            "path_params": path_params(path_template),
            "query_params": sorted(model["query_params"]),
            "body_params": request_field_index.get(key, []),
            "request_schema_ref": str(request_refs[0]) if request_refs else None,
            "response_schema_ref": str(response_refs[0]) if response_refs else None,
            "request_schema_refs": [str(item) for item in request_refs if item],
            "response_schema_refs": [str(item) for item in response_refs if item],
            "status_codes": sorted(int(item) for item in model["status_codes"] if item is not None),
            "semantic_tags": semantic_tags(path_template, method, semantic),
            "risk_tags": risk_tags(path_template, method, semantic),
            "related_artifacts": {
                "request_schema_refs": [str(item) for item in request_refs if item],
                "response_schema_refs": [str(item) for item in response_refs if item],
                "semantic_id": semantic.get("semantic_id"),
            },
        }
        output.append(compact_endpoint_model(item))
    return sorted(
        output,
        key=lambda item: (
            str(item.get("origin") or ""),
            str(item.get("path_template") or ""),
            str(item.get("method") or ""),
        ),
    )


def base_model(method: str, url: str, path_template: str) -> dict[str, Any]:
    return {
        "method": method,
        "origin": endpoint_origin(url),
        "path_template": path_template,
        "observed_urls": set(),
        "raw_paths": set(),
        "source": set(),
        "source_evidence": [],
        "query_params": set(),
        "status_codes": set(),
        "auth_required": False,
        "confidence": 0.4,
    }


def merge_sources(model: dict[str, Any], sources: Any) -> None:
    if isinstance(sources, list):
        for source in sources:
            if str(source):
                model["source"].add(str(source))
    elif sources:
        model["source"].add(str(sources))


def template_path(path: str) -> str:
    segments = [segment for segment in path.split("/") if segment]
    output: list[str] = []
    for _index, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            output.append(segment)
            continue
        previous = output[-1].strip("{}") if output else ""
        if is_variable_segment(segment):
            output.append("{" + identifier_name(previous) + "}")
        else:
            output.append(segment)
    return "/" + "/".join(output)


def is_variable_segment(segment: str) -> bool:
    return segment.isdigit() or bool(UUID_RE.match(segment)) or bool(HEX_RE.match(segment))


def identifier_name(previous_segment: str) -> str:
    base = previous_segment.strip("/").replace("-", "_")
    if not base:
        return "id"
    if base.endswith("ies"):
        base = f"{base[:-3]}y"
    elif base.endswith("s") and len(base) > 3:
        base = base[:-1]
    return f"{to_camel(base)}Id"


def to_camel(value: str) -> str:
    parts = [part for part in re.split(r"[_\-\s]+", value) if part]
    if not parts:
        return "object"
    return parts[0].lower() + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def endpoint_origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def endpoint_model_id(method: str, origin: str, path_template: str) -> str:
    return f"{method} {path_template}" if not origin else f"{method} {origin}{path_template}"


def schemas_by_endpoint(
    schemas: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    output: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for schema in schemas:
        url = str(schema.get("url") or "")
        method = str(schema.get("method") or "GET").upper()
        if not url:
            continue
        parsed = urlparse(url)
        key = (method, endpoint_origin(url), template_path(parsed.path or "/"))
        output.setdefault(key, []).append(schema)
    return output


def schema_field_names_by_endpoint(
    schemas: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[str]]:
    output: dict[tuple[str, str, str], set[str]] = {}
    for schema in schemas:
        url = str(schema.get("url") or "")
        method = str(schema.get("method") or "GET").upper()
        if not url:
            continue
        parsed = urlparse(url)
        key = (method, endpoint_origin(url), template_path(parsed.path or "/"))
        for field in schema.get("fields") or []:
            if not isinstance(field, dict):
                continue
            name = str(field.get("path") or field.get("name") or "")
            if name:
                output.setdefault(key, set()).add(name)
    return {key: sorted(values) for key, values in output.items()}


def semantic_by_model(records: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    output: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        url = str(record.get("url") or "")
        method = str(record.get("method") or "GET").upper()
        if not url:
            continue
        parsed = urlparse(url)
        key = (method, endpoint_origin(url), template_path(parsed.path or "/"))
        output.setdefault(key, record)
    return output


def path_params(path_template: str) -> list[str]:
    return re.findall(r"\{([^{}]+)\}", path_template)


def resource_from_template(path_template: str) -> str:
    segments = [
        segment
        for segment in path_template.split("/")
        if segment and not (segment.startswith("{") and segment.endswith("}"))
    ]
    if not segments:
        return "unknown"
    return normalize_resource_name(segments[-1])


def normalize_resource_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    if normalized.endswith("ies"):
        return f"{normalized[:-3]}y"
    if normalized.endswith("s") and len(normalized) > 3:
        return normalized[:-1]
    return normalized or "unknown"


def operation_from_method(method: str) -> str:
    if method == "GET":
        return "read"
    if method == "POST":
        return "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "DELETE":
        return "delete"
    return method.lower()


def operation_type(method: str, action: Any) -> str:
    action_value = str(action or "").lower()
    if action_value in {"list", "read", "search"}:
        return "read"
    if action_value in {"create", "submit", "invite", "upload"}:
        return "create"
    if action_value in {"update", "approve", "reject", "publish", "archive", "grade"}:
        return "mutate"
    if action_value == "delete":
        return "delete"
    return operation_from_method(method)


def semantic_tags(path_template: str, method: str, semantic: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    object_ids = semantic.get("object_id_params") or path_params(path_template)
    if object_ids:
        tags.add("object_scoped_resource")
    text = path_template.lower()
    if any(marker in text for marker in ("org", "tenant", "workspace", "team")):
        tags.add("tenant_scoped_resource")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        tags.add("state_changing_operation")
    if semantic.get("auth_guess") in {
        "admin_or_staff",
        "member_or_owner",
        "owner_or_authorized_actor",
    }:
        tags.add(str(semantic.get("auth_guess")))
    return sorted(tags)


def risk_tags(path_template: str, method: str, semantic: dict[str, Any]) -> list[str]:
    tags: set[str] = set()
    text = path_template.lower()
    if semantic.get("object_id_params") or path_params(path_template):
        tags.add("BOLA")
    if any(marker in text for marker in ("admin", "role", "permission", "billing", "refund")):
        tags.add("BFLA")
    if method in {"POST", "PUT", "PATCH"}:
        tags.add("MASS_ASSIGNMENT")
    if any(
        marker in text for marker in ("export", "download", "invoice", "billing", "user", "profile")
    ):
        tags.add("EXCESSIVE_DATA_EXPOSURE")
    if any(marker in text for marker in ("url", "callback", "webhook", "redirect", "file", "path")):
        tags.add("SINK_REVIEW")
    return sorted(tags)


def source_confidence(source: Any) -> float:
    sources = source if isinstance(source, list) else [source]
    mapping = {
        "har": 0.95,
        "traffic": 0.95,
        "openapi": 0.9,
        "openapi_fixture": 0.9,
        "js_static": 0.75,
        "js_fixture": 0.75,
        "api_collection": 0.85,
        "archive": 0.55,
        "archive_fixture": 0.55,
    }
    values = [mapping.get(str(item), 0.5) for item in sources if item is not None]
    return max(values) if values else 0.5


def compact_endpoint_model(item: dict[str, Any]) -> dict[str, Any]:
    item["model_hash"] = stable_id(
        "api_endpoint_model",
        item.get("method"),
        item.get("origin"),
        item.get("path_template"),
    )
    return {key: value for key, value in item.items() if value not in (None, "", [], {})}
