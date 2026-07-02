from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from donzo.config import ScopeConfig
from donzo.models import (
    Asset,
    Endpoint,
    Finding,
    Service,
    clamp_confidence,
    normalize_severity,
    normalize_source,
)
from donzo.scope import parse_target


def normalize_asset_lines(
    lines: list[str],
    *,
    config: ScopeConfig,
    source: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for line in lines:
        target = extract_asset_target(line)
        if not target:
            removed.append({"record": line, "reason": "missing asset"})
            continue
        decision = config.scope.decide(target)
        if not decision.allowed:
            removed.append({"record": line, "reason": "; ".join(decision.reasons)})
            continue
        parsed = parse_target(target)
        asset_value = parsed.host or parsed.raw
        asset_type = "domain" if parsed.target_type == "url" else parsed.target_type
        asset = Asset(
            asset=asset_value,
            type=asset_type,
            sources=[source],
            in_scope=True,
            risk_hints=asset_risk_hints(asset_value),
        )
        assets.append(asset.to_dict())
    return assets, removed


def normalize_httpx_records(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    services: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for record in records:
        url = str(record.get("url") or record.get("input") or record.get("host") or "")
        if not url:
            removed.append({"record": record, "reason": "missing url"})
            continue
        decision = config.scope.decide(url)
        if not decision.allowed:
            removed.append({"record": record, "reason": "; ".join(decision.reasons)})
            continue
        parsed = urlparse(url)
        tech = record.get("tech") if isinstance(record.get("tech"), list) else []
        service = Service(
            url=url,
            host=parsed.hostname or "",
            status_code=as_int(record.get("status_code") or record.get("status-code")),
            title=string_or_none(record.get("title")),
            content_type=string_or_none(record.get("content_type") or record.get("content-type")),
            tech=[str(item) for item in tech],
            ports=[as_int(record.get("port"))] if as_int(record.get("port")) else [],
            source=["httpx"],
            risk_hints=service_risk_hints(url, record),
        )
        services.append(service.to_dict())
    return services, removed


def normalize_endpoint_records(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    source: str = "endpoint_artifact",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    endpoints: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for record in records:
        url = str(record.get("url") or record.get("target") or record.get("matched-at") or "")
        if not url:
            removed.append({"record": record, "reason": "missing url"})
            continue
        decision = config.scope.decide(url)
        if not decision.allowed:
            removed.append({"record": record, "reason": "; ".join(decision.reasons)})
            continue
        method = str(record.get("method") or "GET").upper()
        endpoint = Endpoint(
            url=url,
            method=method,
            source=[source],
            status_code=as_int(record.get("status_code") or record.get("status-code")),
            content_type=string_or_none(record.get("content_type") or record.get("content-type")),
            params=endpoint_params(url, record),
            requires_auth_guess=auth_guess(record),
            risk_hints=endpoint_risk_hints(url, record),
        )
        endpoints.append(endpoint.to_dict())
    return endpoints, removed


def normalize_finding_records(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for record in records:
        target = str(record.get("target") or record.get("url") or record.get("matched-at") or "")
        if not target:
            removed.append({"record": record, "reason": "missing target"})
            continue
        decision = config.scope.decide(target)
        if not decision.allowed:
            removed.append({"record": record, "reason": "; ".join(decision.reasons)})
            continue
        title = str(
            record.get("title")
            or record.get("name")
            or record.get("template-id")
            or "Untitled Finding"
        )
        candidate_type = str(
            record.get("candidate_type")
            or record.get("type")
            or record.get("matcher-name")
            or "GENERAL_CANDIDATE"
        ).upper()
        finding = Finding(
            title=title,
            severity=normalize_severity(record.get("severity")),
            confidence=clamp_confidence(record.get("confidence")),
            target=target,
            candidate_type=candidate_type,
            source=normalize_source(record.get("source") or record.get("tool") or "scanner"),
            evidence=record.get("evidence") if isinstance(record.get("evidence"), dict) else {},
            verification_status=str(record.get("verification_status") or "needs_manual_review"),
            manual_verification=manual_verification_steps(candidate_type),
        )
        findings.append(finding.to_dict())
    return findings, removed


def as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def string_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def extract_asset_target(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    return stripped.split()[0].strip(",")


def asset_risk_hints(asset: str) -> list[str]:
    lowered = asset.lower()
    hints: list[str] = []
    if "api" in lowered:
        hints.append("api_asset")
    if any(marker in lowered for marker in ("dev", "staging", "test")):
        hints.append("non_prod_keyword")
    if any(marker in lowered for marker in ("admin", "internal")):
        hints.append("sensitive_keyword")
    return hints


def endpoint_params(url: str, record: dict[str, Any]) -> list[str]:
    params = record.get("params")
    if isinstance(params, list):
        return [str(item) for item in params]
    parsed = urlparse(url)
    return sorted(parse_qs(parsed.query).keys())


def auth_guess(record: dict[str, Any]) -> bool | None:
    if "requires_auth_guess" in record:
        return bool(record["requires_auth_guess"])
    status = as_int(record.get("status_code") or record.get("status-code"))
    if status in {401, 403}:
        return True
    return None


def service_risk_hints(url: str, record: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    lowered = url.lower()
    title = str(record.get("title") or "").lower()
    if "api" in lowered or "api" in title:
        hints.append("api_service")
    if any(marker in lowered for marker in ("dev", "staging", "test")):
        hints.append("non_prod_keyword")
    if any(marker in lowered for marker in ("admin", "internal")):
        hints.append("sensitive_keyword")
    return hints


def endpoint_risk_hints(url: str, record: dict[str, Any]) -> list[str]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    params = endpoint_params(url, record)
    hints: list[str] = []
    if any(marker in path for marker in ("swagger", "openapi", "api-docs", "redoc")):
        hints.append("api_docs")
    if any(marker in path for marker in ("graphql", "graphiql", "playground")):
        hints.append("graphql")
    if any(marker in path for marker in ("order", "invoice", "account", "user", "document")):
        hints.append("object_resource")
    if any(name.lower() in {"id", "user_id", "order_id", "account_id"} for name in params):
        hints.append("object_id_parameter")
    return hints


def manual_verification_steps(candidate_type: str) -> list[str]:
    if candidate_type in {"BOLA_IDOR", "IDOR"}:
        return [
            "Use authorized test accounts only.",
            "Confirm object ownership and expected authorization behavior manually.",
            "Do not enumerate IDs or access real user data.",
        ]
    if candidate_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER"}:
        return [
            "Confirm whether exposed documentation is intended by the program.",
            "Check for sensitive non-public endpoints without executing unsafe operations.",
        ]
    return ["Confirm scope and reproduce manually with safe read-only checks."]
