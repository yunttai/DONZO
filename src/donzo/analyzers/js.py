from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from donzo.config import ScopeConfig
from donzo.normalize.artifacts import normalize_endpoint_records

JS_ENDPOINT_PATTERN = re.compile(
    r"""(?P<quote>["'`])(?P<value>(?:https?://[^"'`\s<>]+|/[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+))(?P=quote)"""
)
JS_TEMPLATE_PATTERN = re.compile(r"`(?P<value>(?:https?://|/)[^`]+)`")
FETCH_METHOD_PATTERN = re.compile(r"""method\s*:\s*["'](?P<method>[A-Za-z]+)["']""", re.I)
AXIOS_METHOD_PATTERN = re.compile(
    r"""(?:axios|client|api)\.(?P<method>get|post|put|patch|delete)\s*\($""",
    re.I,
)

STATIC_SUFFIXES = (
    ".css",
    ".gif",
    ".ico",
    ".jpg",
    ".jpeg",
    ".map",
    ".png",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
)
APP_ROUTE_MARKERS = (
    "/lms",
    "/portal",
    "/dashboard",
    "/app",
    "/admin",
    "/auth",
    "/login",
)
API_ROUTE_MARKERS = (
    "/api",
    "/rest",
    "/rpc",
    "/v1",
    "/v2",
    "/v3",
)


def extract_endpoints_from_js_text(
    text: str,
    *,
    base_url: str,
    config: ScopeConfig,
    source: str = "js_static",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_value, start, end in iter_js_endpoint_matches(text):
        raw_value = normalize_template_endpoint(raw_value)
        url = resolve_js_url(raw_value, base_url)
        if not url or not likely_endpoint_url(url):
            continue
        method = infer_js_method(text, start, end)
        key = (url, method)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "url": url,
                "method": method,
                "source_context": {
                    "js_callsite": infer_js_callsite(text, start),
                    "js_literal": raw_value[:200],
                },
            }
        )
    endpoints, scoped_removed = normalize_endpoint_records(records, config=config, source=source)
    removed.extend(scoped_removed)
    return endpoints, removed


def iter_js_endpoint_values(text: str) -> list[str]:
    return [value for value, _start, _end in iter_js_endpoint_matches(text)]


def iter_js_endpoint_matches(text: str) -> list[tuple[str, int, int]]:
    values: list[tuple[str, int, int]] = []
    for match in JS_ENDPOINT_PATTERN.finditer(text):
        value = match.group("value").strip()
        if value:
            values.append((value, match.start(), match.end()))
    for match in JS_TEMPLATE_PATTERN.finditer(text):
        value = match.group("value").strip()
        if value:
            values.append((value, match.start(), match.end()))
    return sorted(set(values), key=lambda item: item[0])


def normalize_template_endpoint(value: str) -> str:
    return re.sub(
        r"\$\{\s*([^}:]+).*?\}",
        lambda match: "{" + param_name(match.group(1)) + "}",
        value,
    )


def param_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", value.strip().split(".")[-1]).strip("_")
    return name or "param"


def infer_js_method(text: str, start: int, end: int) -> str:
    prefix = text[max(0, start - 80) : start]
    suffix = text[end : min(len(text), end + 180)]
    axios_match = AXIOS_METHOD_PATTERN.search(prefix)
    if axios_match:
        return axios_match.group("method").upper()
    fetch_match = FETCH_METHOD_PATTERN.search(suffix)
    if fetch_match:
        return fetch_match.group("method").upper()
    return "GET"


def infer_js_callsite(text: str, start: int) -> str:
    prefix = text[max(0, start - 500) : start]
    patterns = (
        r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?",
        r"([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?\(?[^;\n]{0,80}$",
        r"([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^;\n]{0,80}$",
    )
    for pattern in patterns:
        matches = list(re.finditer(pattern, prefix, flags=re.I | re.M))
        if matches:
            return matches[-1].group(1)[:120]
    return ""


def resolve_js_url(value: str, base_url: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    if not base_url:
        return ""
    return urljoin(base_url, value)


def likely_endpoint_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if not parsed.scheme or not parsed.netloc:
        return False
    if path.endswith(STATIC_SUFFIXES):
        return False
    if path.endswith(".js"):
        return True
    return bool(
        parsed.query
        or path.startswith(API_ROUTE_MARKERS)
        or path in APP_ROUTE_MARKERS
        or any(path.startswith(f"{marker}/") for marker in APP_ROUTE_MARKERS)
        or any(marker in path for marker in ("graphql", "swagger", "openapi", "api-docs"))
        or any(marker in path for marker in ("admin", "internal", "user", "order", "invoice"))
    )


def js_file_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [endpoint for endpoint in endpoints if is_js_file_url(str(endpoint.get("url") or ""))]


def source_map_endpoints(
    js_files: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    source: str = "sourcemap_candidate",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records = [
        {"url": source_map_url(str(endpoint.get("url") or "")), "method": "GET"}
        for endpoint in js_files
        if is_js_file_url(str(endpoint.get("url") or ""))
    ]
    return normalize_endpoint_records(records, config=config, source=source)


def source_map_url(url: str) -> str:
    return f"{url.split('#', 1)[0].split('?', 1)[0]}.map"


def graphql_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        endpoint
        for endpoint in endpoints
        if "graphql" in {str(item) for item in endpoint.get("risk_hints") or []}
    ]


def api_doc_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        endpoint
        for endpoint in endpoints
        if "api_docs" in {str(item) for item in endpoint.get("risk_hints") or []}
    ]


def is_js_file_url(url: str) -> bool:
    return urlparse(url).path.lower().endswith(".js")
