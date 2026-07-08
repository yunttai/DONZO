from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

LLMStatus = Literal[
    "not_submitted",
    "submitted",
    "running",
    "succeeded",
    "failed",
    "schema_invalid",
    "retry_exceeded",
    "pending_batch",
    "rate_limited",
    "timeout",
]

VerificationStatus = Literal[
    "llm_pending",
    "llm_failed",
    "llm_schema_invalid",
    "likely_false_positive",
    "needs_manual_review",
    "likely_true_positive",
    "confirmed_candidate",
    "out_of_scope_or_not_allowed",
]

Verdict = Literal[
    "confirmed_candidate",
    "likely_true_positive",
    "needs_manual_review",
    "likely_false_positive",
    "out_of_scope_or_not_allowed",
]

Priority = Literal["P0", "P1", "P2", "P3"]

NOT_ALLOWED_ACTIONS = [
    "automatic exploit",
    "automatic submission",
    "destructive testing",
    "credential attack",
    "secret validation",
    "subdomain takeover claim",
]

FINDING_VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://donzo.local/schemas/finding-verdict.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "confidence",
        "priority",
        "risk_score_adjustment",
        "impact_assessment",
        "manual_verification_required",
        "manual_verification_steps",
        "false_positive_reasons",
        "not_allowed_actions",
    ],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": [
                "confirmed_candidate",
                "likely_true_positive",
                "needs_manual_review",
                "likely_false_positive",
                "out_of_scope_or_not_allowed",
            ],
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "priority": {"type": "string", "enum": ["P0", "P1", "P2", "P3", "IGNORE"]},
        "risk_score_adjustment": {"type": "integer", "minimum": -100, "maximum": 100},
        "impact_assessment": {"type": "string", "minLength": 1},
        "manual_verification_required": {"type": "boolean"},
        "manual_verification_steps": {"type": "array", "items": {"type": "string"}},
        "false_positive_reasons": {"type": "array", "items": {"type": "string"}},
        "not_allowed_actions": {"type": "array", "items": {"type": "string"}},
    },
}

CLUSTER_VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://donzo.local/schemas/cluster-verdict.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "cluster_verdict",
        "priority",
        "confidence",
        "risk_score_adjustment",
        "impact_assessment",
        "manual_verification_required",
        "manual_verification_steps",
        "false_positive_reasons",
        "not_allowed_actions",
    ],
    "properties": {
        "cluster_verdict": {
            "type": "string",
            "enum": [
                "confirmed_candidate",
                "likely_true_positive",
                "needs_manual_review",
                "likely_false_positive",
                "out_of_scope_or_not_allowed",
            ],
        },
        "priority": {"type": "string", "enum": ["P0", "P1", "P2", "P3", "IGNORE"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "risk_score_adjustment": {"type": "integer", "minimum": -100, "maximum": 100},
        "impact_assessment": {"type": "string", "minLength": 1},
        "manual_verification_required": {"type": "boolean"},
        "manual_verification_steps": {"type": "array", "items": {"type": "string"}},
        "false_positive_reasons": {"type": "array", "items": {"type": "string"}},
        "not_allowed_actions": {"type": "array", "items": {"type": "string"}},
    },
}

CANDIDATE_GENERATION_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://donzo.local/schemas/candidate-generation.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": ["stage", "candidates", "excluded", "safety_notes"],
    "properties": {
        "stage": {"type": "string", "const": "candidate_generator"},
        "candidates": {
            "type": "array",
            "maxItems": 25,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "candidate_type",
                    "target",
                    "severity",
                    "confidence",
                    "reason",
                    "manual_verification_steps",
                    "auto_exploit",
                ],
                "properties": {
                    "candidate_type": {"type": "string", "minLength": 1},
                    "target": {"type": "string", "minLength": 1},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "reason": {"type": "array", "items": {"type": "string"}},
                    "manual_verification_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "auto_exploit": {"type": "boolean", "const": False},
                },
            },
        },
        "excluded": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["target", "reason"],
                "properties": {
                    "target": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
        "safety_notes": {"type": "array", "items": {"type": "string"}},
    },
}

REPORT_DRAFT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://donzo.local/schemas/report-draft.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": ["stage", "markdown", "included_findings", "excluded_findings", "safety_notes"],
    "properties": {
        "stage": {"type": "string", "const": "report_writer"},
        "markdown": {"type": "string", "minLength": 1},
        "included_findings": {"type": "array", "items": {"type": "string"}},
        "excluded_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["target", "reason"],
                "properties": {
                    "target": {"type": "string"},
                    "reason": {"type": "string"},
                },
            },
        },
        "safety_notes": {"type": "array", "items": {"type": "string"}},
    },
}


@dataclass(frozen=True)
class EvidenceSummary:
    target: str
    finding_type: str
    observed_facts: list[str]
    missing_evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "finding_type": self.finding_type,
            "observed_facts": self.observed_facts,
            "missing_evidence": self.missing_evidence,
        }


@dataclass(frozen=True)
class EvidencePack:
    program: str
    target: str
    candidate_type: str
    scope_summary: dict[str, Any]
    candidate: dict[str, Any]
    evidence: dict[str, Any]
    safety_constraints: dict[str, bool]
    redactions_applied: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "target": self.target,
            "candidate_type": self.candidate_type,
            "scope_summary": self.scope_summary,
            "candidate": self.candidate,
            "evidence": self.evidence,
            "safety_constraints": self.safety_constraints,
            "redactions_applied": self.redactions_applied,
        }


@dataclass(frozen=True)
class FindingVerdict:
    verdict: Verdict
    confidence: float
    priority: Priority | Literal["IGNORE"]
    risk_score_adjustment: int
    impact_assessment: str
    manual_verification_required: bool
    manual_verification_steps: list[str]
    false_positive_reasons: list[str]
    not_allowed_actions: list[str] = field(default_factory=lambda: list(NOT_ALLOWED_ACTIONS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "priority": self.priority,
            "risk_score_adjustment": self.risk_score_adjustment,
            "impact_assessment": self.impact_assessment,
            "manual_verification_required": self.manual_verification_required,
            "manual_verification_steps": self.manual_verification_steps,
            "false_positive_reasons": self.false_positive_reasons,
            "not_allowed_actions": self.not_allowed_actions,
        }


@dataclass(frozen=True)
class MandatoryLLMResult:
    llm_required: bool
    fail_closed: bool
    driver: str
    llm_status: LLMStatus
    verification_status: VerificationStatus
    include_in_final_report: bool
    evidence_pack: EvidencePack
    verdict: FindingVerdict | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "llm_required": self.llm_required,
            "fail_closed": self.fail_closed,
            "driver": self.driver,
            "llm_status": self.llm_status,
            "verification_status": self.verification_status,
            "include_in_final_report": self.include_in_final_report,
            "evidence_pack": self.evidence_pack.to_dict(),
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "error": self.error,
        }
