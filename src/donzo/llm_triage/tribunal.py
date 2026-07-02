from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from donzo.config import LLMConfig, ScopeConfig
from donzo.llm_triage.drivers.anthropic_api import AnthropicDriver
from donzo.llm_triage.drivers.base import LLMCallError, LLMSchemaError, TribunalDriver
from donzo.llm_triage.drivers.codex_cli import CodexCliDriver
from donzo.llm_triage.drivers.openai_api import OpenAIDriver
from donzo.llm_triage.evidence_pack import build_evidence_pack
from donzo.llm_triage.schema import MandatoryLLMResult

TRIAGE_CANDIDATE_TYPES = {
    "BOLA_IDOR",
    "IDOR",
    "EXPOSED_API_DOCS",
    "PUBLIC_SWAGGER",
    "GRAPHQL",
    "GRAPHQL_INTROSPECTION",
    "SECRET_EXPOSURE",
    "LEAKED_SECRET",
    "SUBDOMAIN_TAKEOVER",
    "TAKEOVER",
    "SSRF",
    "FILE_DISCLOSURE",
    "ADMIN_PANEL",
    "OPEN_REDIRECT",
}

LOW_VALUE_TYPES = {
    "MISSING_SECURITY_HEADER",
    "COOKIE_FLAG",
    "VERSION_DISCLOSURE",
    "BANNER_DISCLOSURE",
    "FAVICON_HASH",
}


def load_finding(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8").strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("finding input must be one JSON object")
    return data


def should_triage_with_llm(finding: dict[str, Any]) -> bool:
    finding_type = str(
        finding.get("candidate_type")
        or finding.get("type")
        or finding.get("matcher-name")
        or ""
    ).upper()
    severity = str(finding.get("severity") or "").lower()
    if finding_type in LOW_VALUE_TYPES:
        return False
    if finding_type in TRIAGE_CANDIDATE_TYPES:
        return True
    return severity in {"medium", "high", "critical"}


def run_tribunal(
    finding: dict[str, Any],
    *,
    config: ScopeConfig | None = None,
    llm_config: LLMConfig,
    driver_name: str = "auto",
    allow_external_llm: bool = False,
    target_allowed: bool = True,
) -> MandatoryLLMResult:
    if config is None:
        raise ValueError("ScopeConfig is required to build a safe Evidence Pack")
    evidence_pack = build_evidence_pack(config, finding)
    if not target_allowed:
        return MandatoryLLMResult(
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=selected_driver_name(llm_config, driver_name),
            llm_status="not_submitted",
            verification_status="out_of_scope_or_not_allowed",
            include_in_final_report=False,
            evidence_pack=evidence_pack,
            error="target is out of scope or policy disallows this item",
        )
    driver = build_driver(
        llm_config,
        driver_name=driver_name,
        allow_external_llm=allow_external_llm,
    )
    try:
        verdict = driver.judge(evidence_pack)
    except LLMSchemaError as exc:
        return MandatoryLLMResult(
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=driver.name,
            llm_status="schema_invalid",
            verification_status="llm_schema_invalid",
            include_in_final_report=False,
            evidence_pack=evidence_pack,
            error=str(exc),
        )
    except LLMCallError as exc:
        return MandatoryLLMResult(
            llm_required=llm_config.required,
            fail_closed=llm_config.fail_closed,
            driver=driver.name,
            llm_status="failed",
            verification_status="llm_failed",
            include_in_final_report=False,
            evidence_pack=evidence_pack,
            error=str(exc),
        )
    return MandatoryLLMResult(
        llm_required=llm_config.required,
        fail_closed=llm_config.fail_closed,
        driver=driver.name,
        llm_status="succeeded",
        verification_status=verdict.verdict,
        include_in_final_report=verdict.verdict
        not in {"likely_false_positive", "out_of_scope_or_not_allowed"},
        evidence_pack=evidence_pack,
        verdict=verdict,
    )


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
    raise ValueError(f"Unsupported external tribunal driver: {selected}")


def selected_driver_name(llm_config: LLMConfig, driver_name: str) -> str:
    return llm_config.primary_provider if driver_name == "auto" else driver_name
