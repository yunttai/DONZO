from __future__ import annotations

from typing import Any

from donzo.analyzers.parameter_classifier import classify_parameter


def classify_field(
    name: str, *, location: str = "body", field_type: str = "", path: str = ""
) -> dict[str, Any]:
    return classify_parameter(
        "field_semantics",
        name,
        location,
        field_type=field_type,
        path=path,
    )


def classify_fields(
    fields: list[dict[str, Any]], *, location: str = "body"
) -> list[dict[str, Any]]:
    return [
        classify_field(
            str(field.get("name") or field.get("path") or ""),
            location=str(field.get("location") or location),
            field_type=str(field.get("type") or ""),
            path=str(field.get("path") or ""),
        )
        for field in fields
        if isinstance(field, dict) and str(field.get("name") or field.get("path") or "")
    ]
