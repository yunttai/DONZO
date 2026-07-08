from __future__ import annotations

from typing import Any

from donzo.models import stable_id


def build_ui_field_usage(
    schema_diffs: list[dict[str, Any]],
    *,
    request_schemas: list[dict[str, Any]],
    response_schemas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    request_fields = top_level_fields_by_endpoint(request_schemas)
    response_fields = top_level_fields_by_endpoint(response_schemas)
    output: list[dict[str, Any]] = []
    for diff in schema_diffs:
        read_endpoint = str(diff.get("read_endpoint") or "")
        write_endpoint = str(diff.get("write_endpoint") or "")
        if not read_endpoint:
            continue
        ui_consumed = sorted(request_fields.get(write_endpoint, set()))
        api_response = sorted(response_fields.get(read_endpoint, set()))
        excessive = [
            field
            for field in (
                diff.get("excessive_data_candidates") or diff.get("read_only_candidates") or []
            )
            if field in api_response and field not in ui_consumed
        ]
        output.append(
            {
                "ui_field_usage_id": stable_id("ui_field_usage", read_endpoint, write_endpoint),
                "page": "unknown",
                "api_endpoint": read_endpoint,
                "write_endpoint": write_endpoint,
                "ui_consumed_fields": ui_consumed,
                "api_response_fields": api_response,
                "excessive_data_candidates": excessive,
                "confidence": 0.45 if ui_consumed else 0.25,
                "evidence": ["inferred from observed write-body fields and read response schema"],
            }
        )
    return output


def top_level_fields_by_endpoint(schemas: list[dict[str, Any]]) -> dict[str, set[str]]:
    output: dict[str, set[str]] = {}
    for schema in schemas:
        endpoint_id = str(schema.get("endpoint_id") or "")
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
