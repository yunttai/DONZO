from __future__ import annotations

from typing import Any

from donzo.analyzers.parameter_classifier import classify_parameter
from donzo.models import stable_id


def build_schema_diffs(
    api_endpoint_models: list[dict[str, Any]],
    *,
    request_schemas: list[dict[str, Any]],
    response_schemas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    reads = [
        endpoint
        for endpoint in api_endpoint_models
        if str(endpoint.get("operation_type") or "") == "read"
    ]
    writes = [
        endpoint
        for endpoint in api_endpoint_models
        if str(endpoint.get("operation_type") or "") in {"create", "mutate", "update", "delete"}
    ]
    request_fields = top_level_fields_by_endpoint(request_schemas)
    response_fields = top_level_fields_by_endpoint(response_schemas)
    output: list[dict[str, Any]] = []
    for read in reads:
        read_endpoint_id = str(read.get("endpoint_id") or "")
        read_fields = response_fields.get(read_endpoint_id, set())
        if not read_fields:
            continue
        for write in writes:
            if not likely_same_resource(read, write):
                continue
            write_endpoint_id = str(write.get("endpoint_id") or "")
            write_fields = request_fields.get(write_endpoint_id, set())
            read_only = sorted(read_fields - write_fields)
            mass_assignment = [
                name
                for name in read_only
                if classify_parameter(write_endpoint_id, name, "body")["semantic_class"]
                in {
                    "role_field",
                    "permission_field",
                    "privilege_flag",
                    "state_field",
                    "money_field",
                    "tenant_identifier",
                    "object_identifier",
                    "user_identifier",
                }
            ]
            excessive = [
                name
                for name in read_only
                if classify_parameter(read_endpoint_id, name, "response")["semantic_class"]
                in {
                    "email_field",
                    "sensitive_field",
                    "money_field",
                    "role_field",
                    "permission_field",
                    "privilege_flag",
                }
            ]
            if not read_only and not mass_assignment and not excessive:
                continue
            output.append(
                {
                    "schema_diff_id": stable_id("schema_diff", read_endpoint_id, write_endpoint_id),
                    "resource": read.get("resource") or write.get("resource") or "unknown",
                    "read_endpoint": read_endpoint_id,
                    "write_endpoint": write_endpoint_id,
                    "read_only_candidates": read_only[:100],
                    "mass_assignment_candidates": mass_assignment[:50],
                    "excessive_data_candidates": excessive[:50],
                    "rationale": (
                        "fields appear in observed GET response but are not observed in "
                        "legitimate write request body"
                    ),
                    "confidence": diff_confidence(read_only, mass_assignment, excessive),
                }
            )
    return output


def top_level_fields_by_endpoint(schemas: list[dict[str, Any]]) -> dict[str, set[str]]:
    output: dict[str, set[str]] = {}
    for schema in schemas:
        endpoint_id = str(schema.get("endpoint_id") or schema.get("endpoint_model_id") or "")
        if not endpoint_id:
            from donzo.analyzers.parameter_classifier import derive_endpoint_id

            endpoint_id = derive_endpoint_id(
                str(schema.get("method") or "GET").upper(),
                str(schema.get("url") or ""),
            )
        fields = {
            str(field.get("name") or "")
            for field in schema.get("fields") or []
            if isinstance(field, dict)
            and str(field.get("name") or "")
            and "." not in str(field.get("path") or field.get("name") or "")
        }
        output.setdefault(endpoint_id, set()).update(fields)
    return output


def likely_same_resource(read: dict[str, Any], write: dict[str, Any]) -> bool:
    if read.get("origin") and write.get("origin") and read.get("origin") != write.get("origin"):
        return False
    if read.get("resource") and read.get("resource") == write.get("resource"):
        return True
    read_path = str(read.get("path_template") or "")
    write_path = str(write.get("path_template") or "")
    return bool(
        read_path
        and write_path
        and (read_path.startswith(write_path) or write_path.startswith(read_path))
    )


def diff_confidence(
    read_only: list[str],
    mass_assignment: list[str],
    excessive: list[str],
) -> float:
    confidence = 0.45
    if read_only:
        confidence += 0.12
    if mass_assignment:
        confidence += 0.18
    if excessive:
        confidence += 0.15
    return round(min(confidence, 0.9), 2)
