from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from jsonschema import Draft202012Validator

from donzo.llm_triage.schema import (
    FINDING_VERDICT_JSON_SCHEMA,
    EvidencePack,
    FindingVerdict,
)


class LLMCallError(RuntimeError):
    """External LLM call failed or was not allowed."""


class LLMSchemaError(LLMCallError):
    """External LLM returned output that failed the required schema."""


class TribunalDriver(ABC):
    name: str

    @abstractmethod
    def judge(self, evidence_pack: EvidencePack) -> FindingVerdict:
        """Call an external LLM and return a schema-constrained verdict."""


def verdict_from_mapping(data: dict[str, Any]) -> FindingVerdict:
    validate_verdict_mapping(data)
    return FindingVerdict(
        verdict=data["verdict"],
        confidence=float(data["confidence"]),
        priority=data["priority"],
        risk_score_adjustment=int(data["risk_score_adjustment"]),
        impact_assessment=str(data["impact_assessment"]),
        manual_verification_required=bool(data["manual_verification_required"]),
        manual_verification_steps=[str(item) for item in data["manual_verification_steps"]],
        false_positive_reasons=[str(item) for item in data["false_positive_reasons"]],
        not_allowed_actions=[str(item) for item in data["not_allowed_actions"]],
    )


def validate_verdict_mapping(data: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(FINDING_VERDICT_JSON_SCHEMA).iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(item) for item in first.absolute_path) or "<root>"
        raise LLMSchemaError(f"verdict schema invalid at {path}: {first.message}")
