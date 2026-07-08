from __future__ import annotations

from pathlib import Path
from typing import Any

from donzo.models import stable_id
from donzo.storage.jsonl import load_json_records

DEFAULT_ACTOR_ORDER = [
    "user_A",
    "user_B",
    "admin",
    "member",
    "other_org_user",
    "anonymous",
]

SAFE_CREDENTIAL_REF_PREFIXES = ("env:", "vault:", "keychain:", "1password:", "op://", "none")
SECRET_FIELD_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "session",
    "authorization",
    "credential",
)


def load_actor_records(paths: list[Path] | None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths or []:
        records.extend(load_json_records(path))
    return records


def build_actor_model(
    records: list[dict[str, Any]] | None = None,
    *,
    traffic: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    actor_records = [normalize_actor_record(item) for item in records or []]
    traffic_records = actor_records_from_traffic(traffic or [])
    actors = merge_actor_records(actor_records + traffic_records)
    relationships = build_actor_relationships(actors)
    owned_resources = build_owned_resources(actors)
    warnings = actor_model_warnings(records or [])
    return {
        "actor_model_id": stable_id(
            "actor_model",
            [actor.get("actor_id") for actor in actors],
            [actor.get("role") for actor in actors],
            [actor.get("tenant") for actor in actors],
        ),
        "actors": actors,
        "relationships": relationships,
        "owned_resources": owned_resources,
        "warnings": warnings,
        "summary": actor_model_summary(actors),
    }


def normalize_actor_record(record: dict[str, Any]) -> dict[str, Any]:
    actor_id = str(record.get("actor_id") or record.get("actor") or record.get("name") or "unknown")
    role = str(record.get("role") or infer_role(actor_id))
    tenant = str(record.get("tenant") or record.get("organization") or record.get("org") or "")
    credential_ref = safe_credential_ref(
        str(record.get("credential_ref") or record.get("credential") or "")
    )
    owned = normalize_owned_resources(record.get("owned_resources") or record.get("owns") or [])
    relationships = normalize_relationships(
        record.get("relationships") or record.get("relationship_to") or {}
    )
    item = {
        "actor_id": actor_id,
        "role": role,
        "tenant": tenant or "unknown",
        "owned_resources": owned,
        "relationship_to": relationships,
        "credential_ref": credential_ref,
        "credential_storage": "reference_only",
        "auth_material_persisted": False,
    }
    return compact_empty(item)


def actor_records_from_traffic(traffic: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for record in traffic:
        actor_id = str(record.get("actor") or "unknown")
        if not actor_id or actor_id == "unknown":
            continue
        existing = seen.setdefault(
            actor_id,
            {
                "actor_id": actor_id,
                "role": str(record.get("role") or infer_role(actor_id)),
                "tenant": str(record.get("tenant") or "unknown"),
                "owned_resources": [],
                "relationship_to": {},
                "credential_ref": "",
            },
        )
        if record.get("tenant") and existing.get("tenant") == "unknown":
            existing["tenant"] = str(record.get("tenant"))
        if record.get("role") and existing.get("role") == infer_role(actor_id):
            existing["role"] = str(record.get("role"))
    return [normalize_actor_record(item) for item in seen.values()]


def merge_actor_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        actor_id = str(record.get("actor_id") or "unknown")
        if not actor_id:
            continue
        target = merged.setdefault(
            actor_id,
            {
                "actor_id": actor_id,
                "role": infer_role(actor_id),
                "tenant": "unknown",
                "owned_resources": [],
                "relationship_to": {},
                "credential_ref": "",
                "credential_storage": "reference_only",
                "auth_material_persisted": False,
            },
        )
        if record.get("role"):
            target["role"] = record["role"]
        if record.get("tenant") and record.get("tenant") != "unknown":
            target["tenant"] = record["tenant"]
        if record.get("credential_ref"):
            target["credential_ref"] = record["credential_ref"]
        target["owned_resources"] = merge_lists(
            target.get("owned_resources"), record.get("owned_resources")
        )
        relationship_to = target.setdefault("relationship_to", {})
        for key, value in (record.get("relationship_to") or {}).items():
            relationship_to[str(key)] = str(value)
    if not merged:
        merged["anonymous"] = normalize_actor_record(
            {
                "actor_id": "anonymous",
                "role": "anonymous",
                "tenant": "public",
                "credential_ref": "none",
            }
        )
    return sorted(
        [compact_empty(item) for item in merged.values()],
        key=lambda item: actor_sort_key(str(item.get("actor_id") or "")),
    )


def build_actor_relationships(actors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(actor.get("actor_id") or ""): actor for actor in actors}
    output: list[dict[str, Any]] = []
    for source in actors:
        source_id = str(source.get("actor_id") or "")
        for target_id, relationship in (source.get("relationship_to") or {}).items():
            output.append(
                {
                    "relationship_id": stable_id(
                        "actor_relationship", source_id, target_id, relationship
                    ),
                    "source_actor": source_id,
                    "target_actor": str(target_id),
                    "relationship": str(relationship),
                    "same_tenant": source.get("tenant")
                    == by_id.get(str(target_id), {}).get("tenant"),
                }
            )
    if (
        "user_A" in by_id
        and "user_B" in by_id
        and not any(
            item.get("source_actor") == "user_A" and item.get("target_actor") == "user_B"
            for item in output
        )
    ):
        output.append(
            {
                "relationship_id": stable_id(
                    "actor_relationship", "user_A", "user_B", "separate_test_account"
                ),
                "source_actor": "user_A",
                "target_actor": "user_B",
                "relationship": "separate_test_account",
                "same_tenant": by_id["user_A"].get("tenant") == by_id["user_B"].get("tenant"),
            }
        )
    return output


def build_owned_resources(actors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for actor in actors:
        actor_id = str(actor.get("actor_id") or "")
        for resource in actor.get("owned_resources") or []:
            output.append(
                {
                    "owned_resource_id": stable_id("owned_resource", actor_id, resource),
                    "actor_id": actor_id,
                    "tenant": actor.get("tenant"),
                    "resource": resource,
                    "safe_fixture_only": True,
                }
            )
    return output


def actor_context_for_endpoint(
    endpoint: dict[str, Any],
    actor_model: dict[str, Any] | None,
) -> dict[str, Any]:
    if not actor_model:
        return {}
    actors = actor_model.get("actors") or []
    actor_ids = [str(actor.get("actor_id") or "") for actor in actors]
    return compact_empty(
        {
            "available_actors": actor_ids,
            "baseline_actor": first_present(actor_ids, ["user_A", "member", "admin", "anonymous"]),
            "comparison_actor": first_present(actor_ids, ["user_B", "other_org_user", "anonymous"]),
            "privileged_actor": first_present(actor_ids, ["admin"]),
            "tenant_context": sorted(
                {str(actor.get("tenant")) for actor in actors if actor.get("tenant")}
            ),
            "resource": endpoint.get("resource"),
            "credential_policy": "safe references only; raw credentials are not persisted",
        }
    )


def actor_model_summary(actors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "actor_count": len(actors),
        "actors": [str(actor.get("actor_id") or "") for actor in actors],
        "roles": sorted({str(actor.get("role")) for actor in actors if actor.get("role")}),
        "tenants": sorted({str(actor.get("tenant")) for actor in actors if actor.get("tenant")}),
        "has_ab_pair": any(actor.get("actor_id") == "user_A" for actor in actors)
        and any(actor.get("actor_id") == "user_B" for actor in actors),
        "credential_policy": "reference_only",
    }


def actor_model_warnings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    for index, record in enumerate(records, start=1):
        for key, value in record.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized == "credential_ref":
                ref = str(value or "")
                if ref and not ref.startswith(SAFE_CREDENTIAL_REF_PREFIXES):
                    warnings.append(
                        {
                            "record": index,
                            "field": key,
                            "warning": "credential_ref_not_safe_reference",
                        }
                    )
                continue
            if any(marker in normalized for marker in SECRET_FIELD_MARKERS) and value:
                warnings.append(
                    {"record": index, "field": key, "warning": "raw_credential_field_redacted"}
                )
    return warnings


def safe_credential_ref(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith(SAFE_CREDENTIAL_REF_PREFIXES):
        return text
    return "[REDACTED]"


def normalize_owned_resources(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted({str(item) for item in value if str(item)})
    if isinstance(value, dict):
        return sorted({f"{key}:{item}" for key, item in value.items() if str(item)})
    if value:
        return [str(value)]
    return []


def normalize_relationships(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items() if str(key)}
    if isinstance(value, list):
        output: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            target = str(item.get("target") or item.get("actor") or item.get("target_actor") or "")
            relationship = str(item.get("relationship") or item.get("type") or "related")
            if target:
                output[target] = relationship
        return output
    return {}


def merge_lists(left: Any, right: Any) -> list[str]:
    output = {str(item) for item in left or [] if str(item)}
    output.update(str(item) for item in right or [] if str(item))
    return sorted(output)


def infer_role(actor_id: str) -> str:
    normalized = actor_id.lower()
    if normalized == "anonymous":
        return "anonymous"
    if "admin" in normalized:
        return "admin"
    if "member" in normalized:
        return "member"
    return "user"


def first_present(values: list[str], candidates: list[str]) -> str:
    for candidate in candidates:
        if candidate in values:
            return candidate
    return values[0] if values else ""


def actor_sort_key(actor_id: str) -> tuple[int, str]:
    if actor_id in DEFAULT_ACTOR_ORDER:
        return (DEFAULT_ACTOR_ORDER.index(actor_id), actor_id)
    return (len(DEFAULT_ACTOR_ORDER), actor_id)


def compact_empty(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, "", [], {})}
