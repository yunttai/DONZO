from __future__ import annotations

import re
from typing import Any

from donzo.models import stable_id

TENANT_MARKERS = {"org", "organization", "workspace", "tenant", "team", "group", "company"}
USER_MARKERS = {"user", "account", "member", "owner", "customer", "student", "profile"}
ROLE_MARKERS = {"role", "access_level", "accesslevel"}
PRIVILEGE_MARKERS = {"is_admin", "isadmin", "admin", "is_owner", "isowner", "owner", "superuser"}
PERMISSION_MARKERS = {"permission", "permissions", "scope", "scopes", "capability"}
STATE_MARKERS = {"status", "state", "phase", "step", "approved", "verified", "enabled", "disabled"}
MONEY_MARKERS = {"price", "amount", "total", "balance", "credit", "discount", "coupon", "plan"}
QUANTITY_MARKERS = {"quantity", "qty", "count", "limit", "page", "size"}
URL_MARKERS = {"url", "uri", "redirect", "next", "callback", "webhook", "avatar_url", "avatarurl"}
FILE_MARKERS = {"file", "path", "folder", "key", "object_key", "objectkey", "download"}
FILENAME_MARKERS = {"filename", "file_name", "name"}
SEARCH_MARKERS = {"q", "query", "search", "keyword"}
SORT_MARKERS = {"sort", "orderby", "order_by", "order"}
FILTER_MARKERS = {"filter", "where"}
TEMPLATE_MARKERS = {"template", "html", "markdown"}
TOKEN_MARKERS = {"token", "jwt", "code", "nonce", "secret", "session"}
EMAIL_MARKERS = {"email", "mail"}
SENSITIVE_MARKERS = {"phone", "address", "ssn", "birth", "birthday", "ip", "mfa", "otp"}


def build_parameter_classifications(
    api_endpoint_models: list[dict[str, Any]],
    *,
    request_schemas: list[dict[str, Any]] | None = None,
    response_schemas: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    request_fields = fields_by_endpoint(request_schemas or [])
    response_fields = fields_by_endpoint(response_schemas or [])
    output: list[dict[str, Any]] = []
    for endpoint in api_endpoint_models:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        parameters: list[dict[str, Any]] = []
        for name in endpoint.get("path_params") or []:
            parameters.append(classify_parameter(endpoint_id, str(name), "path"))
        for name in endpoint.get("query_params") or []:
            parameters.append(classify_parameter(endpoint_id, str(name), "query"))
        for field in request_fields.get(endpoint_id, []):
            parameters.append(
                classify_parameter(
                    endpoint_id,
                    str(field.get("name") or field.get("path") or ""),
                    "body",
                    field_type=str(field.get("type") or ""),
                    path=str(field.get("path") or ""),
                )
            )
        for field in response_fields.get(endpoint_id, []):
            parameters.append(
                classify_parameter(
                    endpoint_id,
                    str(field.get("name") or field.get("path") or ""),
                    "response",
                    field_type=str(field.get("type") or ""),
                    path=str(field.get("path") or ""),
                )
            )
        parameters = dedupe_parameters(parameters)
        risk_tags = sorted({tag for item in parameters for tag in item.get("risk_tags") or []})
        output.append(
            {
                "classification_id": stable_id("parameter_classification", endpoint_id),
                "endpoint_id": endpoint_id,
                "method": endpoint.get("method"),
                "path_template": endpoint.get("path_template"),
                "parameters": parameters,
                "risk_tags": risk_tags,
                "confidence": classification_confidence(parameters),
            }
        )
    return output


def classify_parameter(
    endpoint_id: str,
    name: str,
    location: str,
    *,
    field_type: str = "",
    path: str = "",
) -> dict[str, Any]:
    normalized = normalize_name(name)
    semantic_class = semantic_class_for_name(normalized, location)
    risk_tags = risk_tags_for_class(semantic_class, location)
    relevance = security_relevance(semantic_class)
    return {
        "parameter_id": stable_id("classified_parameter", endpoint_id, location, path or name),
        "name": name,
        "path": path or name,
        "location": location,
        "type": field_type or "unknown",
        "semantic_class": semantic_class,
        "security_relevance": relevance,
        "confidence": confidence_for_class(semantic_class, normalized),
        "risk_tags": risk_tags,
    }


def semantic_class_for_name(name: str, location: str) -> str:
    singular = singularize(name)
    base = strip_id_suffix(singular)
    if name in {"id", "uuid"} or name.endswith("_id") or location == "path" and base:
        if base in TENANT_MARKERS:
            return "tenant_identifier"
        if base in USER_MARKERS:
            return "user_identifier"
        return "object_identifier"
    if base in TENANT_MARKERS:
        return "tenant_identifier"
    if base in USER_MARKERS:
        return "user_identifier"
    if name in ROLE_MARKERS or base in ROLE_MARKERS:
        return "role_field"
    if name in PRIVILEGE_MARKERS or base in PRIVILEGE_MARKERS:
        return "privilege_flag"
    if name in PERMISSION_MARKERS or base in PERMISSION_MARKERS:
        return "permission_field"
    if name in STATE_MARKERS or base in STATE_MARKERS:
        return "state_field"
    if name in MONEY_MARKERS or base in MONEY_MARKERS:
        return "money_field"
    if name in QUANTITY_MARKERS or base in QUANTITY_MARKERS:
        return "quantity_field"
    if name in URL_MARKERS or base in URL_MARKERS:
        if "webhook" in name:
            return "webhook_field"
        if "callback" in name:
            return "callback_field"
        return "url_field"
    if "filename" in name or "file_name" in name:
        return "filename_field"
    if name in FILENAME_MARKERS and ("file" in name or location in {"body", "query"}):
        return "filename_field"
    if name in FILE_MARKERS or base in FILE_MARKERS:
        return "path_field" if "path" in name else "file_field"
    if name in SEARCH_MARKERS:
        return "search_query"
    if name in SORT_MARKERS:
        return "sort_field"
    if name in FILTER_MARKERS:
        return "filter_field"
    if name in TEMPLATE_MARKERS or base in TEMPLATE_MARKERS:
        return "template_field"
    if name in TOKEN_MARKERS or base in TOKEN_MARKERS:
        return "token_field"
    if name in EMAIL_MARKERS or base in EMAIL_MARKERS:
        return "email_field"
    if name in SENSITIVE_MARKERS or base in SENSITIVE_MARKERS:
        return "sensitive_field"
    return "unknown"


def risk_tags_for_class(semantic_class: str, location: str) -> list[str]:
    tags: set[str] = set()
    if semantic_class in {"object_identifier", "tenant_identifier", "user_identifier"}:
        tags.add("BOLA")
    if semantic_class in {"role_field", "permission_field", "privilege_flag"}:
        tags.update({"BFLA", "PRIVILEGE_ESCALATION"})
    if (
        semantic_class
        in {
            "role_field",
            "permission_field",
            "privilege_flag",
            "state_field",
            "money_field",
        }
        and location == "body"
    ):
        tags.add("MASS_ASSIGNMENT")
    if (
        semantic_class
        in {
            "email_field",
            "sensitive_field",
            "money_field",
            "privilege_flag",
        }
        and location == "response"
    ):
        tags.add("EXCESSIVE_DATA_EXPOSURE")
    if semantic_class in {
        "url_field",
        "callback_field",
        "webhook_field",
        "file_field",
        "path_field",
        "filename_field",
        "template_field",
    }:
        tags.add("SINK_REVIEW")
    return sorted(tags)


def security_relevance(semantic_class: str) -> str:
    if semantic_class in {"role_field", "permission_field", "privilege_flag", "token_field"}:
        return "critical"
    if semantic_class in {
        "tenant_identifier",
        "object_identifier",
        "user_identifier",
        "state_field",
        "money_field",
        "url_field",
        "callback_field",
        "webhook_field",
        "file_field",
        "path_field",
        "filename_field",
        "template_field",
    }:
        return "high"
    if semantic_class in {"email_field", "sensitive_field", "quantity_field"}:
        return "medium"
    return "low"


def confidence_for_class(semantic_class: str, name: str) -> float:
    if semantic_class == "unknown":
        return 0.25
    if name in {"id", "uuid"}:
        return 0.55
    return 0.85


def classification_confidence(parameters: list[dict[str, Any]]) -> float:
    if not parameters:
        return 0.0
    return round(
        sum(float(item.get("confidence") or 0) for item in parameters) / len(parameters),
        2,
    )


def fields_by_endpoint(schemas: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for schema in schemas:
        endpoint_id = str(schema.get("endpoint_id") or schema.get("endpoint_model_id") or "")
        if not endpoint_id:
            method = str(schema.get("method") or "GET").upper()
            url = str(schema.get("url") or "")
            endpoint_id = derive_endpoint_id(method, url)
        output.setdefault(endpoint_id, []).extend(
            field for field in schema.get("fields") or [] if isinstance(field, dict)
        )
    return output


def derive_endpoint_id(method: str, url: str) -> str:
    from urllib.parse import urlparse

    from donzo.analyzers.api_model import endpoint_origin, template_path

    parsed = urlparse(url)
    origin = endpoint_origin(url)
    path_template = template_path(parsed.path or "/")
    return f"{method} {origin}{path_template}" if origin else f"{method} {path_template}"


def dedupe_parameters(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for parameter in parameters:
        key = (
            str(parameter.get("location") or ""),
            str(parameter.get("path") or ""),
            str(parameter.get("semantic_class") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(parameter)
    return output


def normalize_name(value: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9_]+", "_", spaced.lower()).strip("_")


def strip_id_suffix(value: str) -> str:
    if value.endswith("_id"):
        return value[: -len("_id")]
    if value.endswith("id") and len(value) > 2:
        return value[: -len("id")]
    return value


def singularize(value: str) -> str:
    if value.endswith("ies"):
        return f"{value[:-3]}y"
    if value.endswith("s") and len(value) > 3:
        return value[:-1]
    return value
