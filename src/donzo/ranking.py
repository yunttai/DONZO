from __future__ import annotations

from typing import Any

SEVERITY_SCORE = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 0,
}

BOUNTY_LIKELIHOOD = {
    "BOLA_IDOR": 35,
    "IDOR": 35,
    "SECRET_EXPOSURE": 30,
    "LEAKED_SECRET": 30,
    "SUBDOMAIN_TAKEOVER": 30,
    "TAKEOVER": 30,
    "EXPOSED_API_DOCS": 25,
    "PUBLIC_SWAGGER": 25,
    "GRAPHQL": 25,
    "GRAPHQL_INTROSPECTION": 25,
    "ADMIN_PANEL": 22,
    "SOURCE_MAP_EXPOSURE": 12,
    "SSRF": 20,
    "FILE_DISCLOSURE": 20,
    "OPEN_REDIRECT": 8,
}


def rank_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = [rank_record(record) for record in records]
    return sorted(ranked, key=lambda item: float(item.get("risk_score", 0)), reverse=True)


def rank_record(record: dict[str, Any]) -> dict[str, Any]:
    output = dict(record)
    severity = str(record.get("severity") or "info").lower()
    candidate_type = str(record.get("candidate_type") or "").upper()
    confidence = float(record.get("confidence") or 0)
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    verification = (
        evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
    )
    score = SEVERITY_SCORE.get(severity, 0)
    score += int(confidence * 25)
    score += BOUNTY_LIKELIHOOD.get(candidate_type, 5)
    if evidence:
        score += 10
    verification_status = str(record.get("verification_status") or "")
    if verification_status == "verified":
        score += 10
    elif candidate_type in {"EXPOSED_API_DOCS", "GRAPHQL", "SOURCE_MAP_EXPOSURE"}:
        score -= 20
    if verification.get("schema_verified"):
        score += 10
    if verification.get("sensitive_path_hints"):
        score += 5
    if verification.get("has_sources_content"):
        score += 8
    if verification_status in {"llm_failed", "llm_schema_invalid", "filtered_out"}:
        score -= 100
    score = max(0, min(100, score))
    output["risk_score"] = score
    output["priority"] = priority_for_score(score)
    return output


def priority_for_score(score: int) -> str:
    if score >= 90:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 45:
        return "P2"
    return "P3"
