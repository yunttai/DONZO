from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from donzo.config import LLMConfig, ScopeConfig
from donzo.llm_triage.drivers.anthropic_api import AnthropicDriver
from donzo.llm_triage.drivers.base import LLMCallError, LLMSchemaError, TribunalDriver
from donzo.llm_triage.drivers.codex_cli import CodexCliDriver
from donzo.llm_triage.drivers.openai_api import OpenAIDriver
from donzo.llm_triage.evidence_pack import redact_value
from donzo.llm_triage.schema import (
    CANDIDATE_GENERATION_JSON_SCHEMA,
    CLUSTER_VERDICT_JSON_SCHEMA,
    REPORT_DRAFT_JSON_SCHEMA,
)

REPORT_EXCLUDED_STATUSES = {
    "llm_pending",
    "llm_failed",
    "llm_schema_invalid",
    "likely_false_positive",
    "out_of_scope_or_not_allowed",
    "false_positive",
}


@dataclass(frozen=True)
class MandatoryStageResult:
    stage: str
    llm_required: bool
    fail_closed: bool
    driver: str
    llm_status: str
    input_count: int
    submitted_count: int
    output: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "llm_required": self.llm_required,
            "fail_closed": self.fail_closed,
            "driver": self.driver,
            "llm_status": self.llm_status,
            "input_count": self.input_count,
            "submitted_count": self.submitted_count,
            "output": self.output,
            "error": self.error,
        }


def load_json_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ValueError(f"{path}:{line_number} must be a JSON object")
            records.append(data)
        return records
    data = json.loads(text)
    if isinstance(data, list):
        if not all(isinstance(item, dict) for item in data):
            raise ValueError(f"{path} must contain only JSON objects")
        return list(data)
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"{path} must contain a JSON object, array, or JSONL records")


def run_candidate_generation(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    llm_config: LLMConfig,
    driver_name: str = "auto",
    allow_external_llm: bool = False,
) -> MandatoryStageResult:
    stage = "candidate_generator"
    selected = selected_driver_name(llm_config, driver_name)
    submitted, excluded = split_in_scope_records(config, records)
    if not submitted:
        return MandatoryStageResult(
            stage=stage,
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=selected,
            llm_status="not_submitted",
            input_count=len(records),
            submitted_count=0,
            output={
                "stage": stage,
                "candidates": [],
                "excluded": excluded,
                "safety_notes": ["No in-scope records were submitted to the LLM stage."],
            },
            error="no in-scope records to submit",
        )
    return run_structured_stage(
        stage=stage,
        records=submitted,
        excluded=excluded,
        config=config,
        llm_config=llm_config,
        driver_name=driver_name,
        allow_external_llm=allow_external_llm,
        output_schema=CANDIDATE_GENERATION_JSON_SCHEMA,
        prompt=(
            "Generate bug bounty candidate objects from the submitted endpoint/API/JS "
            "records. Prefer BOLA_IDOR, EXPOSED_API_DOCS, GRAPHQL, SECRET_EXPOSURE, "
            "SSRF, OPEN_REDIRECT, FILE_DISCLOSURE, ADMIN_PANEL, and TAKEOVER only when "
            "the evidence supports them. Do not invent exploitation. Keep auto_exploit "
            "false and include safe manual verification steps."
        ),
    )


def run_report_draft(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    llm_config: LLMConfig,
    driver_name: str = "auto",
    allow_external_llm: bool = False,
) -> MandatoryStageResult:
    stage = "report_writer"
    selected = selected_driver_name(llm_config, driver_name)
    submitted, excluded = split_report_records(config, records)
    if not submitted:
        return MandatoryStageResult(
            stage=stage,
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=selected,
            llm_status="not_submitted",
            input_count=len(records),
            submitted_count=0,
            output={
                "stage": stage,
                "markdown": "",
                "included_findings": [],
                "excluded_findings": excluded,
                "safety_notes": ["No reportable in-scope findings were submitted."],
            },
            error="no reportable in-scope findings to submit",
        )
    return run_structured_stage(
        stage=stage,
        records=submitted,
        excluded=excluded,
        config=config,
        llm_config=llm_config,
        driver_name=driver_name,
        allow_external_llm=allow_external_llm,
        output_schema=REPORT_DRAFT_JSON_SCHEMA,
        prompt=(
            "Draft a concise Markdown bug bounty recon report for human verification. "
            "Use this structure: Target, Summary, Priority Findings, Out-of-Scope "
            "Removed Items, Appendix. Use neutral candidate language. Include evidence "
            "paths and safe manual verification steps. Do not paste secrets or claim "
            "confirmed exploitation without evidence."
        ),
    )


def run_cluster_triage(
    record: dict[str, Any],
    *,
    config: ScopeConfig,
    llm_config: LLMConfig,
    driver_name: str = "auto",
    allow_external_llm: bool = False,
) -> MandatoryStageResult:
    stage = "cluster_triage"
    selected = selected_driver_name(llm_config, driver_name)
    submitted, excluded = split_in_scope_records(config, [record])
    if not submitted:
        return MandatoryStageResult(
            stage=stage,
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=selected,
            llm_status="not_submitted",
            input_count=1,
            submitted_count=0,
            output=None,
            error="cluster evidence pack is out of scope or missing representative target",
        )
    return run_structured_stage(
        stage=stage,
        records=submitted,
        excluded=excluded,
        config=config,
        llm_config=llm_config,
        driver_name=driver_name,
        allow_external_llm=allow_external_llm,
        output_schema=CLUSTER_VERDICT_JSON_SCHEMA,
        prompt=(
            "Triage exactly one DONZO cluster evidence pack for manual review. "
            "Return one JSON object matching the schema. Treat the cluster as a candidate, "
            "not a confirmed vulnerability. The pack may contain verified, unverified, or "
            "deterministically filtered raw candidates, or passive technology/API "
            "inference context. Prefer likely_false_positive or IGNORE for soft-404, "
            "redirect-only, common error, auth-flow, weak fingerprint, or weak "
            "path-pattern evidence. Do not propose exploitation, destructive testing, "
            "credential attacks, secret validation, or backend claims beyond observed "
            "evidence."
        ),
    )


def run_structured_stage(
    *,
    stage: str,
    records: list[dict[str, Any]],
    excluded: list[dict[str, str]],
    config: ScopeConfig,
    llm_config: LLMConfig,
    driver_name: str,
    allow_external_llm: bool,
    output_schema: dict[str, Any],
    prompt: str,
) -> MandatoryStageResult:
    driver = build_driver(
        llm_config,
        driver_name=driver_name,
        allow_external_llm=allow_external_llm,
    )
    payload = build_stage_payload(config, stage, records, excluded)
    try:
        output = driver_structured_json(driver, stage, payload, output_schema, prompt)
    except LLMSchemaError as exc:
        return MandatoryStageResult(
            stage=stage,
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=driver.name,
            llm_status="schema_invalid",
            input_count=len(records) + len(excluded),
            submitted_count=len(records),
            output=None,
            error=str(exc),
        )
    except LLMCallError as exc:
        return MandatoryStageResult(
            stage=stage,
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=driver.name,
            llm_status="failed",
            input_count=len(records) + len(excluded),
            submitted_count=len(records),
            output=None,
            error=str(exc),
        )
    return MandatoryStageResult(
        stage=stage,
        llm_required=llm_config.required,
        fail_closed=llm_config.fail_closed,
        driver=driver.name,
        llm_status="succeeded",
        input_count=len(records) + len(excluded),
        submitted_count=len(records),
        output=output,
        error=None,
    )


def driver_structured_json(
    driver: TribunalDriver,
    stage: str,
    payload: dict[str, Any],
    output_schema: dict[str, Any],
    prompt: str,
) -> dict[str, Any]:
    if isinstance(driver, CodexCliDriver):
        return driver.structured_json(
            stage=stage,
            payload=payload,
            output_schema=output_schema,
            prompt=prompt,
        )
    raise LLMCallError(f"{driver.name} does not implement structured stage calls yet")


def build_driver(
    llm_config: LLMConfig,
    *,
    driver_name: str = "auto",
    allow_external_llm: bool = False,
) -> TribunalDriver:
    selected = selected_driver_name(llm_config, driver_name)
    if selected == "openai":
        return OpenAIDriver(llm_config, allow_external_llm=allow_external_llm)
    if selected == "anthropic":
        return AnthropicDriver(llm_config, allow_external_llm=allow_external_llm)
    if selected == "codex_cli":
        return CodexCliDriver(llm_config, allow_external_llm=allow_external_llm)
    raise ValueError(f"Unsupported external LLM stage driver: {selected}")


def selected_driver_name(llm_config: LLMConfig, driver_name: str) -> str:
    return llm_config.primary_provider if driver_name == "auto" else driver_name


def split_in_scope_records(
    config: ScopeConfig,
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    submitted: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for record in records:
        target = record_target(record)
        if not target:
            excluded.append({"target": "", "reason": "missing target"})
            continue
        decision = config.scope.decide(target)
        if not decision.allowed:
            excluded.append({"target": target, "reason": "; ".join(decision.reasons)})
            continue
        submitted.append(record)
    return submitted, excluded


def split_report_records(
    config: ScopeConfig,
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    scoped, excluded = split_in_scope_records(config, records)
    submitted: list[dict[str, Any]] = []
    for record in scoped:
        status = str(record.get("verification_status") or "").lower()
        if record.get("include_in_final_report") is False:
            excluded.append(
                {
                    "target": record_target(record),
                    "reason": "include_in_final_report=false",
                }
            )
            continue
        if status in REPORT_EXCLUDED_STATUSES:
            excluded.append(
                {
                    "target": record_target(record),
                    "reason": f"verification_status={status}",
                }
            )
            continue
        submitted.append(record)
    return submitted, excluded


def build_stage_payload(
    config: ScopeConfig,
    stage: str,
    records: list[dict[str, Any]],
    excluded: list[dict[str, str]],
) -> dict[str, Any]:
    redactions: list[str] = []
    max_chars = int(config.llm.privacy_value("max_response_excerpt_chars", 4000))
    return {
        "program": config.program_name,
        "profile": config.profile,
        "stage": stage,
        "scope_summary": {
            "in_scope": list(config.scope.in_scope_domains),
            "out_of_scope": list(config.scope.out_scope_domains),
            "blocked_tests": sorted(config.policy.out_of_scope_test_types),
        },
        "records": redact_value("records", records, redactions, max_chars=max_chars),
        "excluded_before_llm": excluded,
        "safety_constraints": {
            "auto_exploit": False,
            "automatic_submission": False,
            "secret_validation": False,
            "takeover_claim": False,
            "destructive_testing": False,
        },
        "redactions_applied": sorted(set(redactions)),
    }


def record_target(record: dict[str, Any]) -> str:
    direct = str(record.get("target") or record.get("url") or record.get("matched-at") or "")
    if direct:
        return direct
    cluster = record.get("cluster") if isinstance(record.get("cluster"), dict) else {}
    representative = str(cluster.get("representative_target") or "")
    if representative:
        return representative
    targets = cluster.get("targets") if isinstance(cluster.get("targets"), list) else []
    return str(targets[0]) if targets else ""
