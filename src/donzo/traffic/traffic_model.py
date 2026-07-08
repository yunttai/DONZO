from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from donzo.analyzers.api_model import endpoint_origin, template_path
from donzo.models import stable_id


def traffic_endpoint_key(method: str, url: str) -> tuple[str, str, str]:
    parsed = urlparse(url)
    return (method.upper(), endpoint_origin(url), template_path(parsed.path or "/"))


def traffic_endpoint_id(method: str, url: str) -> str:
    method_value, origin, path_template = traffic_endpoint_key(method, url)
    return (
        f"{method_value} {origin}{path_template}" if origin else f"{method_value} {path_template}"
    )


def traffic_record_id(
    *,
    source_file: str,
    sequence_index: int,
    actor: str,
    state: str,
    method: str,
    url: str,
    role: str = "",
    tenant: str = "",
    flow: str = "",
    label: str = "",
) -> str:
    return stable_id(
        "traffic",
        source_file,
        sequence_index,
        actor,
        role,
        tenant,
        state,
        flow,
        label,
        method.upper(),
        url,
    )


def traffic_metadata(record: dict[str, Any]) -> dict[str, Any]:
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    url = str(request.get("url") or "")
    parsed = urlparse(url)
    return {
        "traffic_id": record.get("traffic_id"),
        "actor": record.get("actor"),
        "role": record.get("role"),
        "tenant": record.get("tenant"),
        "state": record.get("state"),
        "flow": record.get("flow"),
        "label": record.get("label"),
        "sequence_index": record.get("sequence_index"),
        "method": str(request.get("method") or "GET").upper(),
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "path_template": template_path(parsed.path or "/"),
    }
