from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from donzo.llm_triage.schema import EvidenceSummary


def summarize_evidence(finding: dict[str, Any]) -> EvidenceSummary:
    target = str(finding.get("target") or finding.get("url") or finding.get("matched-at") or "")
    finding_type = str(
        finding.get("candidate_type")
        or finding.get("type")
        or finding.get("matcher-name")
        or "GENERAL_CANDIDATE"
    ).upper()
    observed = observed_facts(finding, target, finding_type)
    missing = missing_evidence(finding, finding_type)
    return EvidenceSummary(
        target=target,
        finding_type=finding_type,
        observed_facts=observed,
        missing_evidence=missing,
    )


def observed_facts(finding: dict[str, Any], target: str, finding_type: str) -> list[str]:
    facts: list[str] = []
    if target:
        facts.append(f"Target observed: {target}")
    if finding_type:
        facts.append(f"Finding type classified as {finding_type}")
    if severity := finding.get("severity"):
        facts.append(f"Source severity is {severity}")
    if source := finding.get("source") or finding.get("tool"):
        facts.append(f"Source is {source}")
    if status := finding.get("status_code"):
        facts.append(f"HTTP status code observed: {status}")
    if title := finding.get("title"):
        facts.append(f"Title observed: {title}")
    if content_type := finding.get("content_type"):
        facts.append(f"Content-Type observed: {content_type}")
    if params := finding.get("params"):
        facts.append(f"Parameters observed: {params}")
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and evidence:
        facts.append("Evidence object is present")
    facts.extend(type_specific_facts(target, finding_type))
    return facts


def type_specific_facts(target: str, finding_type: str) -> list[str]:
    parsed = urlparse(target)
    path = parsed.path.lower()
    facts: list[str] = []
    if finding_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER", "SWAGGER"} and any(
        marker in path for marker in ("swagger", "openapi", "api-docs", "redoc")
    ):
        facts.append("API documentation path pattern is present")
    if finding_type in {"BOLA_IDOR", "IDOR"} and any(
        marker in path for marker in ("user", "order", "invoice", "document", "account")
    ):
        facts.append("User-owned resource keyword appears in path")
    if finding_type in {"SECRET_EXPOSURE", "LEAKED_SECRET"}:
        facts.append("Secret-like material was reported by source tooling")
    return facts


def missing_evidence(finding: dict[str, Any], finding_type: str) -> list[str]:
    missing: list[str] = []
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        missing.append("No request/response evidence object provided")
    if not finding.get("auth_checked"):
        missing.append("No authentication requirement check performed")
    if finding_type in {"BOLA_IDOR", "IDOR"} and not finding.get("two_account_tested"):
        missing.append("No two-account authorization check performed")
    if finding_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER", "SWAGGER"} and not finding.get(
        "sensitive_paths_confirmed"
    ):
        missing.append("No sensitive documented operation confirmed")
    if finding_type in {"SECRET_EXPOSURE", "LEAKED_SECRET"}:
        missing.append("Secret was not and must not be validated automatically")
    return missing
