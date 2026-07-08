from __future__ import annotations

import json
import textwrap
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import yaml

from donzo.config import ScopeConfig
from donzo.normalize.artifacts import normalize_endpoint_records

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
OPENAPI_SCHEMA_PATHS = (
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
)
OPENAPI_UI_PATHS = (
    "/swagger-ui/index.html",
    "/swagger-ui",
    "/swagger",
    "/docs",
    "/redoc",
)
OPENAPI_DOC_PATHS = (*OPENAPI_SCHEMA_PATHS, *OPENAPI_UI_PATHS)
COMMON_APP_BASE_PATHS = (
    "/lms",
    "/portal",
    "/dashboard",
    "/app",
    "/admin",
    "/docs",
)
COMMON_API_SURFACE_PATHS = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/graphql",
)


def endpoints_from_openapi_document(
    document: dict[str, Any],
    *,
    base_url: str,
    config: ScopeConfig,
    source: str = "openapi",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return [], [{"record": "<openapi>", "reason": "missing paths object"}]
    base_urls = openapi_base_urls(document, fallback_base_url=base_url)
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params = operation_parameters({"parameters": path_item.get("parameters")})
        for method, operation in path_item.items():
            method_lower = str(method).lower()
            if method_lower not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            params = path_parameters(str(path))
            params.extend(path_params)
            params.extend(operation_parameters(operation))
            params.extend(request_body_parameters(operation))
            for resolved_base_url in base_urls:
                records.append(
                    {
                        "url": openapi_url(resolved_base_url, str(path)),
                        "method": method_lower.upper(),
                        "params": sorted(set(params)),
                        "content_type": "application/json",
                        "operation_id": str(operation.get("operationId") or ""),
                        "operation_tags": [
                            str(item) for item in operation.get("tags") or [] if str(item)
                        ][:20],
                        "operation_summary": str(
                            operation.get("summary") or operation.get("description") or ""
                        )[:300],
                        "source_context": {
                            "openapi_path": str(path),
                            "openapi_method": method_lower.upper(),
                        },
                    }
                )
    return normalize_endpoint_records(records, config=config, source=source)


def parse_openapi_document_text(text: str, content_type: str = "") -> dict[str, Any] | None:
    stripped = textwrap.dedent(text).strip()
    if not stripped:
        return None
    parsed: object
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        if not looks_like_yaml_openapi(stripped, content_type):
            return None
        try:
            parsed = yaml.safe_load(stripped)
        except yaml.YAMLError:
            return None
    if not isinstance(parsed, dict):
        return None
    if not ({"openapi", "swagger", "paths"} & set(parsed)):
        return None
    return parsed


def looks_like_yaml_openapi(text: str, content_type: str) -> bool:
    lowered_type = content_type.lower()
    lowered = text[:1000].lower()
    return (
        "yaml" in lowered_type
        or "yml" in lowered_type
        or "openapi:" in lowered
        or "swagger:" in lowered
    )


def openapi_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def openapi_base_urls(document: dict[str, Any], *, fallback_base_url: str) -> list[str]:
    urls: list[str] = []
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict):
                continue
            server_url = str(server.get("url") or "")
            resolved = resolve_server_url(server_url, fallback_base_url)
            if resolved:
                urls.append(resolved)
    swagger_base = swagger2_base_url(document, fallback_base_url)
    if swagger_base:
        urls.append(swagger_base)
    if not urls:
        urls.append(fallback_base_url)
    return dedupe_strings(urls)


def resolve_server_url(server_url: str, fallback_base_url: str) -> str:
    if not server_url:
        return ""
    normalized = server_url.replace("{version}", "v1").replace("{basePath}", "")
    parsed = urlparse(normalized)
    if parsed.scheme and parsed.netloc:
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    return openapi_url(fallback_base_url, normalized)


def swagger2_base_url(document: dict[str, Any], fallback_base_url: str) -> str:
    host = str(document.get("host") or "")
    base_path = str(document.get("basePath") or "")
    schemes = document.get("schemes")
    scheme = "https"
    if isinstance(schemes, list) and schemes:
        scheme = str(schemes[0] or "https")
    if host:
        return urlunparse((scheme, host, base_path.rstrip("/"), "", "", ""))
    if base_path:
        return openapi_url(fallback_base_url, base_path)
    return ""


def openapi_document_candidates(
    endpoints: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    source: str = "openapi_discovery",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    for base_url in endpoint_base_urls(endpoints):
        for path in expanded_openapi_doc_paths():
            records.append({"url": openapi_url(base_url, path), "method": "GET"})
    return normalize_endpoint_records(records, config=config, source=source)


def api_surface_candidates(
    endpoints: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    source: str = "api_surface_discovery",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    for base_url in endpoint_base_urls(endpoints):
        for path in expanded_api_surface_paths():
            records.append({"url": openapi_url(base_url, path), "method": "GET"})
    return normalize_endpoint_records(records, config=config, source=source)


def expanded_openapi_doc_paths() -> tuple[str, ...]:
    paths: list[str] = list(OPENAPI_DOC_PATHS)
    for app_path in COMMON_APP_BASE_PATHS:
        for doc_path in OPENAPI_DOC_PATHS:
            paths.append(f"{app_path.rstrip('/')}/{doc_path.lstrip('/')}")
    return tuple(dedupe_strings(paths))


def expanded_api_surface_paths() -> tuple[str, ...]:
    paths: list[str] = [*COMMON_APP_BASE_PATHS, *COMMON_API_SURFACE_PATHS]
    for app_path in COMMON_APP_BASE_PATHS:
        for api_path in COMMON_API_SURFACE_PATHS:
            paths.append(f"{app_path.rstrip('/')}/{api_path.lstrip('/')}")
    return tuple(dedupe_strings(paths))


def endpoint_base_urls(endpoints: list[dict[str, Any]]) -> list[str]:
    base_urls: list[str] = []
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        if base_url not in base_urls:
            base_urls.append(base_url)
    return sorted(base_urls)


def path_parameters(path: str) -> list[str]:
    params: list[str] = []
    current = ""
    in_param = False
    for char in path:
        if char == "{":
            current = ""
            in_param = True
            continue
        if char == "}" and in_param:
            if current:
                params.append(current)
            in_param = False
            continue
        if in_param:
            current += char
    return params


def operation_parameters(operation: object) -> list[str]:
    if not isinstance(operation, dict):
        return []
    raw_params = operation.get("parameters")
    if not isinstance(raw_params, list):
        return []
    params: list[str] = []
    for item in raw_params:
        if not isinstance(item, dict):
            continue
        location = str(item.get("in") or "").lower()
        name = str(item.get("name") or "")
        if location in {"query", "path"} and name:
            params.append(name)
    return params


def request_body_parameters(operation: object) -> list[str]:
    if not isinstance(operation, dict):
        return []
    params: list[str] = []
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media_type, media_schema in content.items():
                if "json" not in str(media_type) and "form" not in str(media_type):
                    continue
                if isinstance(media_schema, dict):
                    params.extend(schema_property_names(media_schema.get("schema")))
    raw_params = operation.get("parameters")
    if isinstance(raw_params, list):
        for item in raw_params:
            if not isinstance(item, dict):
                continue
            location = str(item.get("in") or "").lower()
            name = str(item.get("name") or "")
            if location in {"formdata", "body"} and name:
                params.append(name)
            if location == "body":
                params.extend(schema_property_names(item.get("schema")))
    return params


def schema_property_names(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [str(name) for name in properties if str(name)]
    return []


def dedupe_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        normalized = value.rstrip("/")
        if normalized and normalized not in output:
            output.append(normalized)
    return output
