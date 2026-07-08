from __future__ import annotations

import re
from typing import Any

from donzo.analyzers.parameter_classifier import classify_parameter
from donzo.fuzzing.models import compact_record, fuzz_candidate_id

SQLI_NAMES = {
    "id",
    "userid",
    "user_id",
    "orderid",
    "order_id",
    "q",
    "query",
    "search",
    "filter",
    "where",
    "sort",
    "category",
    "page",
    "limit",
    "offset",
    "email",
    "username",
    "status",
    "date",
}
SSRF_MARKERS = {
    "url",
    "uri",
    "link",
    "callback",
    "webhook",
    "redirect",
    "next",
    "avatarurl",
    "imageurl",
    "documenturl",
    "feed",
    "import",
    "fetch",
    "proxy",
    "render",
    "pdf",
    "screenshot",
    "preview",
}
SSTI_MARKERS = {"template", "message", "email", "notification", "cms", "preview", "render"}
BFLA_MARKERS = {"admin", "role", "permission", "billing", "refund", "approve", "delete"}
COMMAND_MARKERS = {"cmd", "command", "exec", "shell", "host", "hostname", "lookup", "ping"}
XSS_MARKERS = {"message", "comment", "html", "title", "name", "description", "content"}


def build_fuzz_candidates(
    api_endpoint_models: list[dict[str, Any]],
    *,
    parameter_classifications: list[dict[str, Any]] | None = None,
    schema_diffs: list[dict[str, Any]] | None = None,
    actor_model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    endpoint_index = {str(item.get("endpoint_id") or ""): item for item in api_endpoint_models}
    classification_index = {
        str(item.get("endpoint_id") or ""): item for item in parameter_classifications or []
    }
    output: list[dict[str, Any]] = []
    for endpoint in api_endpoint_models:
        endpoint_id = str(endpoint.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        params = parameters_for_endpoint(endpoint, classification_index.get(endpoint_id, {}))
        for parameter in params:
            for vulnerability_class, reason in classes_for_parameter(endpoint, parameter):
                output.append(candidate_record(endpoint, parameter, vulnerability_class, reason))
        for vulnerability_class, reason in classes_for_endpoint(endpoint):
            output.append(
                candidate_record(
                    endpoint, endpoint_parameter(endpoint), vulnerability_class, reason
                )
            )

    for diff in schema_diffs or []:
        write_endpoint = str(diff.get("write_endpoint") or "")
        read_endpoint = str(diff.get("read_endpoint") or "")
        endpoint = (
            endpoint_index.get(write_endpoint)
            or endpoint_index.get(read_endpoint)
            or {
                "endpoint_id": write_endpoint or read_endpoint,
                "method": "",
                "path_template": "",
            }
        )
        for field in diff.get("mass_assignment_candidates") or []:
            parameter = classify_parameter(
                str(endpoint.get("endpoint_id") or ""), str(field), "body"
            )
            output.append(
                candidate_record(
                    endpoint,
                    parameter,
                    "MASS_ASSIGNMENT",
                    "read-only response field is absent from legitimate write schema",
                )
            )
        for field in diff.get("excessive_data_candidates") or []:
            parameter = classify_parameter(
                str(endpoint.get("endpoint_id") or ""), str(field), "response"
            )
            output.append(
                candidate_record(
                    endpoint,
                    parameter,
                    "EDE",
                    "response field may be unnecessary for the UI or caller contract",
                )
            )

    if actor_model and actor_model.get("relationships"):
        for record in output:
            if record.get("vulnerability_class") in {"BOLA", "BFLA"}:
                record["actor_model_available"] = True
    return dedupe_candidates(output)


def parameters_for_endpoint(
    endpoint: dict[str, Any],
    classification: dict[str, Any],
) -> list[dict[str, Any]]:
    if classification.get("parameters"):
        return [dict(item) for item in classification.get("parameters") or []]
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    output: list[dict[str, Any]] = []
    for name in endpoint.get("path_params") or []:
        output.append(classify_parameter(endpoint_id, str(name), "path"))
    for name in endpoint.get("query_params") or []:
        output.append(classify_parameter(endpoint_id, str(name), "query"))
    for name in endpoint.get("body_params") or []:
        output.append(classify_parameter(endpoint_id, str(name), "body"))
    return output


def classes_for_parameter(
    endpoint: dict[str, Any],
    parameter: dict[str, Any],
) -> list[tuple[str, str]]:
    name = normalize_name(str(parameter.get("name") or parameter.get("path") or ""))
    semantic = str(parameter.get("semantic_class") or "")
    location = str(parameter.get("location") or "")
    classes: list[tuple[str, str]] = []
    if name in SQLI_NAMES or semantic in {"search_query", "filter_field", "sort_field"}:
        classes.append(("SQLI", "parameter name or semantic class is SQL-query-like"))
    if semantic in {"url_field", "callback_field", "webhook_field"} or any(
        marker in name for marker in SSRF_MARKERS
    ):
        classes.append(("SSRF", "parameter can carry a URL or callback destination"))
    if semantic == "template_field" or any(marker in name for marker in SSTI_MARKERS):
        classes.append(("SSTI", "parameter may feed a template or render surface"))
    if semantic in {"object_identifier", "tenant_identifier", "user_identifier"}:
        classes.append(("BOLA", "parameter identifies an object, tenant, or user"))
    if semantic in {"role_field", "permission_field", "privilege_flag"}:
        classes.append(("BFLA", "parameter names role, permission, or privilege"))
    if semantic in {"file_field", "path_field", "filename_field", "template_field"}:
        classes.append(("PATH_TRAVERSAL", "parameter names a file, folder, or path"))
    if location == "body" and semantic in {
        "role_field",
        "permission_field",
        "privilege_flag",
        "state_field",
        "money_field",
        "tenant_identifier",
        "object_identifier",
        "user_identifier",
    }:
        classes.append(("MASS_ASSIGNMENT", "body field may be server-controlled or read-only"))
    if location == "response" and semantic in {
        "email_field",
        "sensitive_field",
        "money_field",
        "role_field",
        "permission_field",
        "privilege_flag",
    }:
        classes.append(("EDE", "response field may be sensitive or unnecessary"))
    if any(marker in name for marker in COMMAND_MARKERS):
        classes.append(("COMMAND_INJECTION", "parameter may reach a shell-like sink"))
    if any(marker in name for marker in XSS_MARKERS):
        classes.append(("XSS", "text-like parameter may be reflected or rendered"))
    if "xml" in name:
        classes.append(("XXE", "XML-like input surface"))
    if semantic in {"file_field", "filename_field"} and str(
        endpoint.get("method") or ""
    ).upper() in {
        "POST",
        "PUT",
        "PATCH",
    }:
        classes.append(("FILE_UPLOAD", "write endpoint carries file metadata"))
    return classes


def classes_for_endpoint(endpoint: dict[str, Any]) -> list[tuple[str, str]]:
    text = " ".join(
        str(endpoint.get(key) or "")
        for key in ("endpoint_id", "path_template", "resource", "action")
    ).lower()
    method = str(endpoint.get("method") or "").upper()
    classes: list[tuple[str, str]] = []
    if any(marker in text for marker in BFLA_MARKERS):
        classes.append(("BFLA", "endpoint path/action is privileged or role-sensitive"))
    if method in {"POST", "PUT", "PATCH", "DELETE"} and any(
        marker in text for marker in {"approve", "refund", "billing", "state", "checkout"}
    ):
        classes.append(("BUSINESS_LOGIC", "state-changing business endpoint"))
    if any(marker in text for marker in {"upload", "avatar", "attachment"}):
        classes.append(("FILE_UPLOAD", "endpoint appears to handle uploaded content"))
    if "xml" in text:
        classes.append(("XXE", "endpoint appears to process XML"))
    return classes


def candidate_record(
    endpoint: dict[str, Any],
    parameter: dict[str, Any],
    vulnerability_class: str,
    reason: str,
) -> dict[str, Any]:
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    candidate = {
        "fuzz_candidate_id": fuzz_candidate_id(endpoint_id, vulnerability_class, parameter),
        "endpoint_id": endpoint_id,
        "method": endpoint.get("method"),
        "path_template": endpoint.get("path_template"),
        "vulnerability_class": vulnerability_class,
        "target_parameter": {
            "name": parameter.get("name"),
            "path": parameter.get("path") or parameter.get("name"),
            "location": parameter.get("location"),
            "semantic_class": parameter.get("semantic_class"),
        },
        "reason": reason,
        "confidence": confidence_for_candidate(vulnerability_class, parameter, endpoint),
        "source": ["fuzz_candidate_selector"],
    }
    return compact_record(candidate)


def endpoint_parameter(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "endpoint",
        "path": str(endpoint.get("path_template") or endpoint.get("endpoint_id") or "endpoint"),
        "location": "endpoint",
        "semantic_class": "endpoint_surface",
    }


def confidence_for_candidate(
    vulnerability_class: str,
    parameter: dict[str, Any],
    endpoint: dict[str, Any],
) -> float:
    base = 0.45
    if parameter.get("semantic_class") not in {None, "", "unknown", "endpoint_surface"}:
        base += 0.2
    if endpoint.get("auth_required"):
        base += 0.05
    if vulnerability_class in set(endpoint.get("risk_tags") or []):
        base += 0.15
    return round(min(base, 0.9), 2)


def dedupe_candidates(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        key = str(record.get("fuzz_candidate_id") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(record)
    return sorted(
        output,
        key=lambda item: (
            str(item.get("endpoint_id") or ""),
            str(item.get("vulnerability_class") or ""),
            str((item.get("target_parameter") or {}).get("path") or ""),
        ),
    )


def normalize_name(value: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9_]+", "_", spaced.lower()).strip("_")
