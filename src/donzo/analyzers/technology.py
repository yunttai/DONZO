from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse

from donzo.models import stable_id

INFERENCE_RULES: tuple[tuple[str, str, float, tuple[str, ...]], ...] = (
    ("nginx", "web_server", 0.7, ("nginx",)),
    ("apache", "web_server", 0.7, ("apache", "httpd")),
    ("microsoft_iis", "web_server", 0.75, ("microsoft-iis", "iis/")),
    ("tomcat", "app_server", 0.75, ("apache-coyote", "tomcat", "jsessionid")),
    ("spring_boot", "backend_framework", 0.72, ("spring", "whitelabel error page")),
    ("django", "backend_framework", 0.72, ("django", "csrftoken")),
    ("flask", "backend_framework", 0.68, ("flask", "werkzeug")),
    ("express", "backend_framework", 0.72, ("express", "x-powered-by: express")),
    ("nodejs", "runtime", 0.65, ("node.js", "nodejs", "next.js", "nuxt")),
    ("php", "runtime", 0.65, ("php", "x-powered-by: php")),
    ("laravel", "backend_framework", 0.72, ("laravel", "laravel_session")),
    ("rails", "backend_framework", 0.7, ("ruby on rails", "x-runtime", "_rails")),
    ("aspnet", "backend_framework", 0.72, ("asp.net", "x-aspnet")),
    ("nextjs", "frontend_framework", 0.75, ("next.js", "_next/", "__next")),
    ("react", "frontend_framework", 0.62, ("react", "vite", "/assets/index-")),
    ("vue", "frontend_framework", 0.62, ("vue", "nuxt", "__nuxt")),
    ("angular", "frontend_framework", 0.62, ("angular", "ng-version")),
    ("swagger_ui", "api_documentation", 0.8, ("swagger-ui", "swagger ui")),
    ("redoc", "api_documentation", 0.8, ("redoc",)),
    ("graphql", "api_protocol", 0.75, ("graphql", "graphiql", "apollo")),
    ("grafana", "admin_or_dev_tool", 0.82, ("grafana",)),
    ("jenkins", "admin_or_dev_tool", 0.82, ("jenkins",)),
    ("kibana", "admin_or_dev_tool", 0.8, ("kibana",)),
    ("prometheus", "admin_or_dev_tool", 0.78, ("prometheus",)),
    ("sonarqube", "admin_or_dev_tool", 0.8, ("sonarqube",)),
    ("portainer", "admin_or_dev_tool", 0.8, ("portainer",)),
    ("phpmyadmin", "admin_or_dev_tool", 0.82, ("phpmyadmin",)),
)

API_PATH_MARKERS = (
    "/api",
    "/rest",
    "/rpc",
    "/graphql",
    "/openapi",
    "/swagger",
    "/api-docs",
    "/v1",
    "/v2",
    "/v3",
)


def build_technology_inferences(
    *,
    services: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    tlsx_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = defaultdict(new_context)
    for service in services:
        origin = service_origin(service)
        if not origin:
            continue
        context = grouped[origin]
        context["origin"] = origin
        context["host"] = urlparse(origin).hostname or str(service.get("host") or "")
        context["sources"].add("service")
        context["service_count"] += 1
        add_service_context(context, service)

    for endpoint in endpoints:
        origin = endpoint_origin(endpoint)
        if not origin:
            continue
        context = grouped[origin]
        context["origin"] = origin
        context["host"] = urlparse(origin).hostname or ""
        context["sources"].add("endpoint")
        context["endpoint_count"] += 1
        add_endpoint_context(context, endpoint)

    for record in tlsx_records or []:
        host = tlsx_host(record)
        if not host:
            continue
        origin = f"https://{host}"
        context = grouped[origin]
        context["origin"] = origin
        context["host"] = host
        context["sources"].add("tlsx")
        add_tlsx_context(context, record)

    inferences = [build_inference(origin, context) for origin, context in grouped.items()]
    inferences = [item for item in inferences if item["technologies"] or item["api_hints"]]
    return sorted(
        inferences,
        key=lambda item: (float(item.get("confidence") or 0), int(item.get("endpoint_count") or 0)),
        reverse=True,
    )


def new_context() -> dict[str, Any]:
    return {
        "origin": "",
        "host": "",
        "sources": set(),
        "service_count": 0,
        "endpoint_count": 0,
        "evidence": [],
        "technology_names": Counter(),
        "technology_categories": {},
        "technology_confidence": {},
        "api_hints": Counter(),
        "tls": {},
    }


def add_service_context(context: dict[str, Any], service: dict[str, Any]) -> None:
    for tech in service.get("tech") or []:
        add_technology(
            context, str(tech), classify_technology(str(tech)), 0.78, f"service.tech:{tech}"
        )
    for key in ("title", "content_type", "url", "host"):
        value = service.get(key)
        if value:
            add_evidence(context, f"{key}:{value}")
            apply_rules(context, str(value), source=f"service.{key}")
    for key in (
        "webserver",
        "web-server",
        "web_server",
        "server",
        "cdn_name",
        "cdn",
        "favicon",
        "favicon_hash",
        "jarm",
        "cname",
    ):
        value = service.get(key)
        if value:
            add_evidence(context, f"{key}:{value}")
            apply_rules(context, str(value), source=f"service.{key}")


def add_endpoint_context(context: dict[str, Any], endpoint: dict[str, Any]) -> None:
    url = str(endpoint.get("url") or "")
    if not url:
        return
    parsed = urlparse(url)
    path = parsed.path.lower() or "/"
    for marker in API_PATH_MARKERS:
        if path == marker or path.startswith(f"{marker}/") or marker in path:
            context["api_hints"][marker] += 1
    hints = endpoint.get("risk_hints") or []
    for hint in hints:
        text = str(hint)
        if text in {"api_route", "api_docs", "graphql", "source_map", "app_route"}:
            context["api_hints"][text] += 1
    add_evidence(context, f"endpoint:{path}")
    apply_rules(context, url, source="endpoint.url")


def add_tlsx_context(context: dict[str, Any], record: dict[str, Any]) -> None:
    for key in ("subject_cn", "issuer_cn", "not_before", "not_after"):
        value = record.get(key)
        if value:
            context["tls"][key] = str(value)
            add_evidence(context, f"tls.{key}:{value}")
    dns_names = record.get("dns_names") or record.get("subject_an") or record.get("san")
    if isinstance(dns_names, list):
        context["tls"]["dns_name_count"] = len(dns_names)
    elif dns_names:
        context["tls"]["dns_name_count"] = 1


def apply_rules(context: dict[str, Any], value: str, *, source: str) -> None:
    lowered = value.lower()
    for name, category, confidence, markers in INFERENCE_RULES:
        if any(marker in lowered for marker in markers):
            add_technology(context, name, category, confidence, f"{source}:{name}")


def add_technology(
    context: dict[str, Any],
    name: str,
    category: str,
    confidence: float,
    evidence: str,
) -> None:
    normalized = normalize_name(name)
    if not normalized:
        return
    context["technology_names"][normalized] += 1
    context["technology_categories"][normalized] = category
    context["technology_confidence"][normalized] = max(
        float(context["technology_confidence"].get(normalized, 0)),
        confidence,
    )
    add_evidence(context, evidence)


def build_inference(origin: str, context: dict[str, Any]) -> dict[str, Any]:
    technologies = [
        {
            "name": name,
            "category": context["technology_categories"].get(name, "unknown"),
            "confidence": round(float(context["technology_confidence"].get(name, 0.5)), 2),
            "observations": count,
        }
        for name, count in context["technology_names"].most_common()
    ]
    api_hints = [
        {"hint": hint, "count": count} for hint, count in context["api_hints"].most_common()
    ]
    confidence_values = [float(item["confidence"]) for item in technologies]
    if api_hints:
        confidence_values.append(0.55)
    confidence = round(max(confidence_values or [0]), 2)
    return {
        "inference_id": stable_id("technology_inference", origin),
        "origin": origin,
        "host": context.get("host") or urlparse(origin).hostname or "",
        "sources": sorted(context["sources"]),
        "service_count": context["service_count"],
        "endpoint_count": context["endpoint_count"],
        "confidence": confidence,
        "technologies": technologies[:20],
        "api_hints": api_hints[:20],
        "tls": context["tls"],
        "evidence": list(dict.fromkeys(context["evidence"]))[:30],
        "automatic_exploit": False,
        "verification_status": "passive_inference",
    }


def service_origin(service: dict[str, Any]) -> str:
    url = str(service.get("url") or "")
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def endpoint_origin(endpoint: dict[str, Any]) -> str:
    url = str(endpoint.get("url") or "")
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def tlsx_host(record: dict[str, Any]) -> str:
    for key in ("host", "ip", "input", "domain"):
        value = str(record.get(key) or "")
        if value:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            return parsed.hostname or value.split(":")[0]
    return ""


def classify_technology(name: str) -> str:
    lowered = name.lower()
    for rule_name, category, _confidence, _markers in INFERENCE_RULES:
        if rule_name in normalize_name(lowered) or any(marker in lowered for marker in _markers):
            return category
    if any(marker in lowered for marker in ("nginx", "apache", "iis")):
        return "web_server"
    if any(marker in lowered for marker in ("react", "vue", "angular", "next", "nuxt")):
        return "frontend_framework"
    if any(marker in lowered for marker in ("spring", "django", "express", "laravel", "rails")):
        return "backend_framework"
    return "unknown"


def normalize_name(value: str) -> str:
    lowered = value.strip().lower()
    if not lowered:
        return ""
    return (
        lowered.replace(" ", "_").replace("/", "_").replace("-", "_").replace(".", "_").strip("_")
    )


def add_evidence(context: dict[str, Any], value: str) -> None:
    text = value.strip()
    if text and len(context["evidence"]) < 60:
        context["evidence"].append(text[:300])
