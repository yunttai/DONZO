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
        service_dict = service.to_dict()
        for key in (
            "webserver",
            "web-server",
            "server",
            "cdn",
            "cdn_name",
            "favicon",
            "favicon_hash",
            "jarm",
            "cname",
            "ip",
            "probe",
        ):
            value = record.get(key)
            if value not in (None, "", [], {}):
                service_dict[key.replace("-", "_")] = value
        services.append(service_dict)
    return services, removed


def normalize_port_records(
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    source: str = "naabu",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    services: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for record in records:
        host = str(record.get("host") or record.get("ip") or record.get("address") or "")
        port = as_int(record.get("port"))
        if not host or port is None:
            removed.append({"record": record, "reason": "missing host or port"})
            continue
        decision = config.scope.decide(host)
        if not decision.allowed:
            removed.append({"record": record, "reason": "; ".join(decision.reasons)})
            continue
        service = Service(
            url=port_service_url(host, port),
            host=host,
            status_code=None,
            ports=[port],
            source=[source],
            risk_hints=port_risk_hints(port),
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
        endpoint_dict = endpoint.to_dict()
        for key in (
            "operation_id",
            "operation_tags",
            "operation_summary",
            "source_context",
            "request_body_fields",
            "response_fields",
        ):
            value = record.get(key)
            if value not in (None, "", [], {}):
                endpoint_dict[key] = trim_metadata_value(value)
        endpoints.append(endpoint_dict)
    return endpoints, removed


def normalize_endpoint_lines(
    lines: list[str],
    *,
    config: ScopeConfig,
    source: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records = [{"url": extract_endpoint_target(line), "method": "GET"} for line in lines]
    records = [record for record in records if record["url"]]
    return normalize_endpoint_records(records, config=config, source=source)


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


def normalize_secret_scan_records(
    records: list[dict[str, Any]],
    *,
    source: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for record in records:
        location = secret_record_location(record)
        detector = secret_record_detector(record, source)
        if not location and not detector:
            removed.append(
                {
                    "record": redacted_secret_record(record),
                    "reason": "missing secret evidence",
                }
            )
            continue
        title = f"Local secret pattern candidate from {source}"
        finding = Finding(
            title=title,
            severity="medium",
            confidence=0.35,
            target=f"local_artifact:{location or source}",
            candidate_type="SECRET_EXPOSURE",
            source=[source],
            evidence={
                "detector": detector,
                "location": location,
                "secret_redacted": True,
                "verification": {
                    "secret_validation_performed": False,
                    "tool_verified": False,
                },
                "record": redacted_secret_record(record),
            },
            verification_status="needs_manual_review",
            manual_verification=manual_verification_steps("SECRET_EXPOSURE"),
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


def extract_endpoint_target(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    target = stripped.split()[0].strip(",")
    if not target.startswith(("http://", "https://")):
        return ""
    return target


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


def port_service_url(host: str, port: int) -> str:
    if port in {443, 8443}:
        return f"https://{host}:{port}"
    if port in {80, 3000, 5000, 8000, 8080, 8888}:
        return f"http://{host}:{port}"
    return f"tcp://{host}:{port}"


def port_risk_hints(port: int) -> list[str]:
    hints: list[str] = []
    if port in {3000, 5000, 8000, 8080, 8888}:
        hints.append("dev_http_port")
    if port in {9200, 9300, 27017, 6379, 11211}:
        hints.append("database_or_cache_port")
    if port in {22, 3389, 5900}:
        hints.append("remote_admin_port")
    return hints


def endpoint_risk_hints(url: str, record: dict[str, Any]) -> list[str]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    params = endpoint_params(url, record)
    title = str(record.get("title") or "").lower()
    tech = " ".join(str(item).lower() for item in record.get("tech") or [])
    hints: list[str] = []
    if path.startswith(("/api", "/rest", "/rpc", "/v1", "/v2", "/v3")):
        hints.append("api_route")
    if path in {"/lms", "/portal", "/dashboard", "/app"} or any(
        path.startswith(f"{marker}/") for marker in ("/lms", "/portal", "/dashboard", "/app")
    ):
        hints.append("app_route")
    if any(marker in path for marker in ("swagger", "openapi", "api-docs", "redoc")):
        hints.append("api_docs")
    if any(marker in path for marker in ("graphql", "graphiql", "playground")):
        hints.append("graphql")
    if path.endswith(".map"):
        hints.append("source_map")
    if any(marker in path for marker in ("order", "invoice", "account", "user", "document")):
        hints.append("object_resource")
    if any(name.lower() in {"id", "user_id", "order_id", "account_id"} for name in params):
        hints.append("object_id_parameter")
    admin_markers = (
        "admin",
        "grafana",
        "jenkins",
        "kibana",
        "sonarqube",
        "prometheus",
        "portainer",
        "phpmyadmin",
    )
    if any(marker in path or marker in title or marker in tech for marker in admin_markers):
        hints.append("admin_panel")
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
    if candidate_type in {"SECRET_EXPOSURE", "LEAKED_SECRET"}:
        return [
            "Review the redacted local artifact manually.",
            "Do not validate, replay, or use any credential-like value.",
            "Rotate the secret through the owner-controlled process if it is real.",
        ]
    return ["Confirm scope and reproduce manually with safe read-only checks."]


def secret_record_location(record: dict[str, Any]) -> str:
    direct = first_string(record, ("File", "file", "path", "SourceName", "source_name"))
    if direct:
        return direct
    source_metadata = record.get("SourceMetadata")
    if isinstance(source_metadata, dict):
        data = source_metadata.get("Data")
        if isinstance(data, dict):
            filesystem = data.get("Filesystem")
            if isinstance(filesystem, dict):
                file_path = first_string(filesystem, ("file", "File", "path", "Path"))
                if file_path:
                    return file_path
    return ""


def secret_record_detector(record: dict[str, Any], source: str) -> str:
    return (
        first_string(
            record,
            (
                "RuleID",
                "rule_id",
                "DetectorName",
                "detector_name",
                "DetectorType",
                "detector_type",
                "Description",
                "description",
            ),
        )
        or source
    )


def first_string(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def redacted_secret_record(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            secret_markers = ("secret", "raw", "token", "password", "credential", "match")
            if any(marker in lowered for marker in secret_markers):
                output[str(key)] = "[REDACTED]"
            else:
                output[str(key)] = redacted_secret_record(item)
        return output
    if isinstance(value, list):
        return [redacted_secret_record(item) for item in value]
    if isinstance(value, str):
        return value[:500]
    return value


def trim_metadata_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): trim_metadata_value(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [trim_metadata_value(item) for item in value[:50]]
    if isinstance(value, str):
        return value[:300]
    return value
