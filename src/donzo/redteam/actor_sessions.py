from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from donzo.actors import SAFE_CREDENTIAL_REF_PREFIXES, SECRET_FIELD_MARKERS
from donzo.models import stable_id
from donzo.storage.jsonl import load_json_records

ACTOR_REQUIRED_CLASSES = {"BOLA", "BFLA", "MASS_ASSIGNMENT", "BUSINESS_LOGIC"}


@dataclass(frozen=True)
class ActorRecord:
    actor_id: str
    role: str = "user"
    tenant: str = "unknown"
    session_ref: str = ""
    owns: dict[str, list[str]] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "role": self.role,
            "tenant": self.tenant,
            "session_ref": self.session_ref,
            "credential_storage": "reference_only",
            "auth_material_persisted": False,
            "owns": self.owns,
            "relationships": self.relationships,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class ActorSessionManager:
    actors: dict[str, ActorRecord]
    relationships: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)

    @property
    def has_actors(self) -> bool:
        return bool(self.actors)

    def actor(self, actor_id: str) -> ActorRecord | None:
        return self.actors.get(actor_id)

    def actor_context(self, actor_id: str) -> dict[str, Any]:
        actor = self.actor(actor_id)
        if not actor:
            return {}
        return {
            "actor_id": actor.actor_id,
            "role": actor.role,
            "tenant": actor.tenant,
            "session_ref": actor.session_ref,
            "credential_storage": "reference_only",
        }

    def requires_actor_model(self, vulnerability_class: str) -> bool:
        return vulnerability_class.strip().upper() in ACTOR_REQUIRED_CLASSES

    def validate_for_class(self, vulnerability_class: str) -> list[str]:
        normalized = vulnerability_class.strip().upper()
        if normalized not in ACTOR_REQUIRED_CLASSES:
            return []
        reasons: list[str] = []
        if not self.actors:
            reasons.append("actors_required")
        if normalized in {"BOLA", "BFLA", "BUSINESS_LOGIC"} and len(self.actors) < 2:
            reasons.append("cross_actor_model_required")
        return reasons

    def summary(self) -> dict[str, Any]:
        return {
            "actor_count": len(self.actors),
            "actors": [actor.to_dict() for actor in self.actors.values()],
            "relationships": self.relationships,
            "warnings": self.warnings,
        }


def load_actor_session_manager(path: Path | None) -> ActorSessionManager:
    if path is None:
        return ActorSessionManager(actors={}, relationships=[], warnings=["actors_yaml_missing"])
    data = load_actor_data(path)
    actors_raw = data.get("actors") if isinstance(data, dict) else []
    relationships = data.get("relationships") if isinstance(data, dict) else []
    if isinstance(actors_raw, dict):
        actors_raw = [
            {"id": key, **value} if isinstance(value, dict) else {"id": key}
            for key, value in actors_raw.items()
        ]
    actors: dict[str, ActorRecord] = {}
    warnings: list[str] = []
    for record in actors_raw or []:
        if not isinstance(record, dict):
            continue
        actor = normalize_actor(record)
        actors[actor.actor_id] = actor
        warnings.extend(f"{actor.actor_id}:{warning}" for warning in actor.warnings)
    return ActorSessionManager(
        actors=dict(sorted(actors.items())),
        relationships=normalize_relationships(relationships or []),
        warnings=warnings,
    )


def load_actor_data(path: Path) -> dict[str, Any]:
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path} must contain a YAML object")
        return data
    if path.suffix.lower() == ".jsonl":
        return {"actors": load_json_records(path), "relationships": []}
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, list):
        return {"actors": data, "relationships": []}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain an object or actor array")
    return data


def normalize_actor(record: dict[str, Any]) -> ActorRecord:
    actor_id = str(record.get("id") or record.get("actor_id") or record.get("actor") or "")
    role = str(record.get("role") or "user")
    tenant = record.get("tenant")
    session_ref = safe_session_ref(
        str(record.get("session_ref") or record.get("credential_ref") or "")
    )
    warnings = raw_secret_warnings(record)
    owns = normalize_owns(record.get("owns") or record.get("owned_resources") or {})
    relationships = normalize_relationships(record.get("relationships") or [])
    if not actor_id:
        actor_id = stable_id("actor", role, tenant, session_ref)
        warnings.append("missing_actor_id_generated")
    return ActorRecord(
        actor_id=actor_id,
        role=role,
        tenant=str(tenant) if tenant is not None else "unknown",
        session_ref=session_ref,
        owns=owns,
        relationships=relationships,
        warnings=warnings,
    )


def safe_session_ref(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith(SAFE_CREDENTIAL_REF_PREFIXES):
        return text
    return "[REDACTED]"


def raw_secret_warnings(record: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    for key, value in record.items():
        normalized = str(key).lower().replace("-", "_")
        if normalized in {"session_ref", "credential_ref"}:
            if value and not str(value).startswith(SAFE_CREDENTIAL_REF_PREFIXES):
                warnings.append(f"{key}:unsafe_reference_redacted")
            continue
        if value and any(marker in normalized for marker in SECRET_FIELD_MARKERS):
            warnings.append(f"{key}:raw_secret_field_ignored")
    return warnings


def normalize_owns(value: Any) -> dict[str, list[str]]:
    if isinstance(value, dict):
        output: dict[str, list[str]] = {}
        for key, items in value.items():
            if isinstance(items, list):
                output[str(key)] = sorted({str(item) for item in items if str(item)})
            elif items not in (None, ""):
                output[str(key)] = [str(items)]
        return output
    if isinstance(value, list):
        return {"resource": sorted({str(item) for item in value if str(item)})}
    return {}


def normalize_relationships(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "relationship_id": str(
                    item.get("relationship_id")
                    or stable_id(
                        "actor_relationship",
                        item.get("subject"),
                        item.get("object"),
                        item.get("relation"),
                    )
                ),
                "subject": item.get("subject"),
                "object": item.get("object"),
                "action": item.get("action"),
                "relation": item.get("relation") or item.get("relationship"),
            }
        )
    return output
