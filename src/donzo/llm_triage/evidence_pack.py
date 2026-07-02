from __future__ import annotations

import hashlib
import re
from typing import Any

from donzo.config import ScopeConfig
from donzo.llm_triage.schema import EvidencePack

SECRET_PATTERNS = {
    "aws_access_key_like": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token_like": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "openai_key_like": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "generic_secret_assignment": re.compile(
        r"(?i)(api[_-]?key|token|secret|password)(\s*[:=]\s*)['\"]?[A-Za-z0-9_./+=-]{12,}"
    ),
}

SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}


def build_evidence_pack(config: ScopeConfig, finding: dict[str, Any]) -> EvidencePack:
    target = str(finding.get("target") or finding.get("url") or finding.get("matched-at") or "")
    candidate_type = str(
        finding.get("candidate_type")
        or finding.get("type")
        or finding.get("matcher-name")
        or "GENERAL_CANDIDATE"
    ).upper()
    redactions: list[str] = []
    candidate = redact_mapping(
        {
            "type": candidate_type,
            "target": target,
            "title": finding.get("title"),
            "source": finding.get("source") or finding.get("tool"),
            "severity": finding.get("severity"),
            "rule_reasons": finding.get("risk_reason") or finding.get("reasons") or [],
        },
        redactions,
        max_chars=int(config.llm.privacy_value("max_response_excerpt_chars", 4000)),
    )
    evidence = redact_mapping(
        {
            "status_code": finding.get("status_code"),
            "content_type": finding.get("content_type"),
            "matched_patterns": finding.get("matched_patterns") or [],
            "request_method": finding.get("method"),
            "auth_guess": finding.get("auth_guess", "unknown"),
            "response_excerpt": finding.get("response_excerpt") or finding.get("body_excerpt"),
            "evidence": finding.get("evidence")
            if isinstance(finding.get("evidence"), dict)
            else {},
        },
        redactions,
        max_chars=int(config.llm.privacy_value("max_response_excerpt_chars", 4000)),
    )
    return EvidencePack(
        program=config.program_name,
        target=target,
        candidate_type=candidate_type,
        scope_summary={
            "in_scope": list(config.scope.in_scope_domains),
            "out_of_scope": list(config.scope.out_scope_domains),
            "blocked_tests": sorted(config.policy.out_of_scope_test_types),
        },
        candidate=candidate,
        evidence=evidence,
        safety_constraints={
            "auto_exploit": False,
            "automatic_submission": False,
            "secret_validation": False,
            "takeover_claim": False,
        },
        redactions_applied=sorted(set(redactions)),
    )


def redact_mapping(
    data: dict[str, Any],
    redactions: list[str],
    *,
    max_chars: int,
) -> dict[str, Any]:
    return {
        key: redact_value(key, value, redactions, max_chars=max_chars)
        for key, value in data.items()
    }


def redact_value(key: str, value: Any, redactions: list[str], *, max_chars: int) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        output = {}
        for item_key, item_value in value.items():
            if str(item_key).lower() in SENSITIVE_HEADER_NAMES:
                redactions.append(f"header:{item_key}")
                output[item_key] = "[REDACTED]"
            else:
                output[item_key] = redact_value(
                    str(item_key),
                    item_value,
                    redactions,
                    max_chars=max_chars,
                )
        return output
    if isinstance(value, list):
        return [redact_value(key, item, redactions, max_chars=max_chars) for item in value]
    if not isinstance(value, str):
        return value
    text = value[:max_chars]
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            redactions.append(label)
            text = redact_pattern(pattern, label, text)
    return text


def redact_pattern(pattern: re.Pattern[str], label: str, text: str) -> str:
    return pattern.sub(lambda match: masked_secret(label, match.group(0)), text)


def masked_secret(label: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"[REDACTED:{label}:sha256:{digest}]"
