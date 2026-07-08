from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin, urlparse

from donzo.config import ScopeConfig
from donzo.normalize.artifacts import normalize_endpoint_records

VARIABLE_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")


def endpoints_from_robots_text(
    text: str,
    *,
    base_url: str,
    config: ScopeConfig,
    source: str = "robots",
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    sitemap_urls: list[str] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        key = key.strip().lower()
        value = raw_value.strip()
        if not value:
            continue
        if key == "sitemap":
            sitemap_url = absolute_url(value, base_url)
            if sitemap_url:
                sitemap_urls.append(sitemap_url)
            continue
        if key not in {"allow", "disallow"}:
            continue
        if value in {"*", "/"} or "*" in value:
            continue
        url = absolute_url(value, base_url)
        if url:
            records.append({"url": url, "method": "GET"})
    endpoints, removed = normalize_endpoint_records(records, config=config, source=source)
    return endpoints, dedupe_strings(sitemap_urls), removed


def endpoints_from_sitemap_text(
    text: str,
    *,
    config: ScopeConfig,
    source: str = "sitemap",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    urls = sitemap_locs(text)
    records = [{"url": url, "method": "GET"} for url in urls]
    return normalize_endpoint_records(records, config=config, source=source)


def sitemap_locs(text: str) -> list[str]:
    stripped = text.strip()
    urls: list[str] = []
    if stripped:
        try:
            root = ET.fromstring(stripped)
            for element in root.iter():
                if element.tag.rsplit("}", 1)[-1].lower() == "loc" and element.text:
                    urls.append(element.text.strip())
        except ET.ParseError:
            urls.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, flags=re.I))
    return dedupe_strings([url for url in urls if url.startswith(("http://", "https://"))])


def endpoints_from_api_collection_document(
    document: dict[str, Any],
    *,
    base_url: str,
    config: ScopeConfig,
    source: str = "api_collection",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    variables = collection_variables(document)
    records: list[dict[str, Any]] = []
    if isinstance(document.get("item"), list):
        records.extend(
            postman_item_records(document.get("item"), variables=variables, base_url=base_url)
        )
    resources = document.get("resources")
    if isinstance(resources, list):
        records.extend(insomnia_request_records(resources, variables=variables, base_url=base_url))
    return normalize_endpoint_records(records, config=config, source=source)


def collection_variables(document: dict[str, Any]) -> dict[str, str]:
    variables: dict[str, str] = {}
    raw_variables = document.get("variable")
    if isinstance(raw_variables, list):
        for item in raw_variables:
            if isinstance(item, dict) and item.get("key"):
                variables[str(item["key"])] = str(item.get("value") or item.get("default") or "")
    resources = document.get("resources")
    if isinstance(resources, list):
        for item in resources:
            if not isinstance(item, dict) or item.get("_type") != "environment":
                continue
            data = item.get("data")
            if isinstance(data, dict):
                variables.update({str(key): str(value) for key, value in data.items()})
    return variables


def postman_item_records(
    items: object,
    *,
    variables: dict[str, str],
    base_url: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return records
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):
            records.extend(
                postman_item_records(item.get("item"), variables=variables, base_url=base_url)
            )
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            continue
        url = postman_request_url(request.get("url"), variables=variables, base_url=base_url)
        if not url:
            continue
        method = str(request.get("method") or "GET").upper()
        records.append(
            {
                "url": url,
                "method": method,
                "source_context": {"collection_item": str(item.get("name") or "")[:200]},
            }
        )
    return records


def postman_request_url(url_data: object, *, variables: dict[str, str], base_url: str) -> str:
    raw = ""
    if isinstance(url_data, str):
        raw = url_data
    elif isinstance(url_data, dict):
        raw = str(url_data.get("raw") or "")
        if not raw:
            path = "/".join(str(item).strip("/") for item in url_data.get("path") or [])
            host = ".".join(str(item) for item in url_data.get("host") or [])
            protocol = str(url_data.get("protocol") or "")
            if host and protocol:
                raw = f"{protocol}://{host}/{path}".rstrip("/")
            elif path:
                raw = f"/{path}"
    return resolve_collection_url(substitute_variables(raw, variables), base_url)


def insomnia_request_records(
    resources: list[object],
    *,
    variables: dict[str, str],
    base_url: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in resources:
        if not isinstance(item, dict) or item.get("_type") != "request":
            continue
        url = resolve_collection_url(
            substitute_variables(str(item.get("url") or ""), variables),
            base_url,
        )
        if not url:
            continue
        records.append(
            {
                "url": url,
                "method": str(item.get("method") or "GET").upper(),
                "source_context": {"collection_item": str(item.get("name") or "")[:200]},
            }
        )
    return records


def substitute_variables(value: str, variables: dict[str, str]) -> str:
    return VARIABLE_PATTERN.sub(lambda match: variables.get(match.group(1), ""), value).strip()


def resolve_collection_url(value: str, base_url: str) -> str:
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    if not base_url:
        return ""
    return urljoin(base_url.rstrip("/") + "/", value.lstrip("/"))


def absolute_url(value: str, base_url: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    if not base_url:
        return ""
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urljoin(f"{parsed.scheme}://{parsed.netloc}/", value.lstrip("/"))


def dedupe_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            output.append(normalized)
            seen.add(normalized)
    return output
