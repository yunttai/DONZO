from __future__ import annotations

from collections import Counter
from typing import Any


def infer_schema(value: Any, *, max_depth: int = 4) -> Any:
    if max_depth <= 0:
        return type_name(value)
    if isinstance(value, dict):
        return {
            str(key): infer_schema(item, max_depth=max_depth - 1)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": "unknown"}
        item_schemas = [infer_schema(item, max_depth=max_depth - 1) for item in value[:20]]
        return {"type": "array", "items": merge_schemas(item_schemas)}
    return type_name(value)


def infer_schema_fields(
    value: Any, *, prefix: str = "", max_depth: int = 4
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    if max_depth <= 0:
        return fields
    if isinstance(value, dict):
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            fields.append({"name": name, "path": path, "type": type_name(item)})
            fields.extend(infer_schema_fields(item, prefix=path, max_depth=max_depth - 1))
    elif isinstance(value, list):
        for item in value[:5]:
            fields.extend(infer_schema_fields(item, prefix=prefix, max_depth=max_depth - 1))
    return dedupe_fields(fields)


def merge_schemas(schemas: list[Any]) -> Any:
    if not schemas:
        return "unknown"
    serialized = [stable_schema_key(schema) for schema in schemas]
    most_common, count = Counter(serialized).most_common(1)[0]
    if count == len(schemas):
        return schemas[serialized.index(most_common)]
    if all(isinstance(schema, dict) and "type" not in schema for schema in schemas):
        keys = sorted({key for schema in schemas for key in schema})
        return {
            key: merge_schemas([schema[key] for schema in schemas if key in schema]) for key in keys
        }
    return {"one_of": sorted(set(serialized))}


def type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def dedupe_fields(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    for field in fields:
        key = (str(field.get("path") or ""), str(field.get("type") or ""))
        if key in seen:
            continue
        seen.add(key)
        output.append(field)
    return output


def stable_schema_key(schema: Any) -> str:
    if isinstance(schema, dict):
        items = ",".join(
            f"{key}:{stable_schema_key(value)}"
            for key, value in sorted(schema.items(), key=lambda pair: str(pair[0]))
        )
        return "{" + items + "}"
    if isinstance(schema, list):
        return "[" + ",".join(stable_schema_key(item) for item in schema) + "]"
    return str(schema)
