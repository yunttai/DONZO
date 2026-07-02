from __future__ import annotations

from typing import Any

from donzo.models import Parameter

IDOR_PARAMETERS = {"id", "user_id", "account_id", "order_id", "invoice_id", "file_id"}
REDIRECT_PARAMETERS = {"next", "url", "redirect", "returnurl", "callback", "continue"}
SSRF_PARAMETERS = {"url", "uri", "endpoint", "host", "domain", "callback", "webhook"}
FILE_PARAMETERS = {"file", "path", "filename", "download", "template", "image"}


def build_parameters_from_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for endpoint in endpoints:
        endpoint_url = str(endpoint.get("url") or "")
        for name in endpoint.get("params") or []:
            parameter = Parameter(
                endpoint_url=endpoint_url,
                name=str(name),
                location="query",
                source=list(endpoint.get("source") or ["endpoint"]),
                risk_hints=parameter_risk_hints(str(name)),
            )
            parameters.append(parameter.to_dict())
    return parameters


def parameter_risk_hints(name: str) -> list[str]:
    normalized = name.strip().lower()
    hints: list[str] = []
    if normalized in IDOR_PARAMETERS:
        hints.append("object_id_parameter")
    if normalized in REDIRECT_PARAMETERS:
        hints.append("redirect_parameter")
    if normalized in SSRF_PARAMETERS:
        hints.append("ssrf_parameter")
    if normalized in FILE_PARAMETERS:
        hints.append("file_parameter")
    return hints
