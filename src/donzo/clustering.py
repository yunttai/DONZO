from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse

from donzo.models import stable_id


def cluster_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[cluster_key(record)].append(record)

    clusters = [build_cluster(key, items) for key, items in grouped.items()]
    return sorted(
        clusters,
        key=lambda item: (float(item.get("risk_score", 0)), int(item.get("count", 0))),
        reverse=True,
    )


def cluster_key(record: dict[str, Any]) -> tuple[str, str]:
    candidate_type = str(record.get("candidate_type") or "GENERAL_CANDIDATE").upper()
    target = str(record.get("target") or record.get("url") or "")
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path.lower()

    if candidate_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER"} or any(
        marker in path for marker in ("swagger", "openapi", "api-docs", "redoc")
    ):
        return ("API_DOCS", host)
    if candidate_type.startswith("GRAPHQL") or "graphql" in path:
        return ("GRAPHQL", host)
    if candidate_type in {"BOLA_IDOR", "IDOR"}:
        return ("OBJECT_ACCESS", host)
    if candidate_type in {"OPEN_REDIRECT", "SSRF", "FILE_DISCLOSURE"}:
        return (candidate_type, host)
    if candidate_type == "ADMIN_PANEL":
        return ("ADMIN_PANEL", host)
    if candidate_type == "SOURCE_MAP_EXPOSURE":
        return (candidate_type, host)
    return (candidate_type, target.lower())


def build_cluster(key: tuple[str, str], records: list[dict[str, Any]]) -> dict[str, Any]:
    cluster_type, scope_key = key
    top = sorted(
        records,
        key=lambda item: float(item.get("risk_score", 0)),
        reverse=True,
    )[0]
    targets = sorted(
        {
            str(item.get("target") or item.get("url") or "")
            for item in records
            if str(item.get("target") or item.get("url") or "")
        }
    )
    record_ids = [
        str(item.get("finding_id") or item.get("candidate_id") or item.get("id") or "")
        for item in records
    ]
    verification_counts = Counter(
        str(item.get("verification_status") or "needs_manual_review") for item in records
    )
    verified_count = verification_counts.get("verified", 0)
    return {
        "cluster_id": stable_id("cluster", cluster_type, scope_key, targets),
        "cluster_type": cluster_type,
        "scope_key": scope_key,
        "title": cluster_title(cluster_type, scope_key),
        "count": len(records),
        "verified_count": verified_count,
        "unverified_count": len(records) - verified_count,
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "evidence_strength": "strong" if verified_count else "weak",
        "targets": targets,
        "record_ids": [item for item in record_ids if item],
        "priority": top.get("priority", "P3"),
        "risk_score": top.get("risk_score", 0),
        "severity": top.get("severity", "info"),
        "manual_verification": merged_manual_steps(records),
    }


def cluster_title(cluster_type: str, scope_key: str) -> str:
    labels = {
        "API_DOCS": "Exposed API documentation candidates",
        "GRAPHQL": "GraphQL exposure candidates",
        "OBJECT_ACCESS": "Object access control candidates",
        "OPEN_REDIRECT": "Open redirect candidates",
        "SSRF": "SSRF parameter candidates",
        "FILE_DISCLOSURE": "File disclosure candidates",
        "ADMIN_PANEL": "Admin or developer interface candidates",
        "SOURCE_MAP_EXPOSURE": "JavaScript source map candidates",
    }
    suffix = f" on {scope_key}" if scope_key else ""
    return f"{labels.get(cluster_type, cluster_type.replace('_', ' ').title())}{suffix}"


def merged_manual_steps(records: list[dict[str, Any]], limit: int = 5) -> list[str]:
    steps: list[str] = []
    for record in records:
        values = record.get("manual_verification") or record.get("manual_verification_steps") or []
        for value in values:
            step = str(value)
            if step and step not in steps:
                steps.append(step)
            if len(steps) >= limit:
                return steps
    return steps
