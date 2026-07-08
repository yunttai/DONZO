from __future__ import annotations

from typing import Any

from donzo.traffic.redactor import redact_headers, redact_value


def redact_request_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": record.get("request_id"),
        "method": record.get("method"),
        "url": record.get("url"),
        "actor": record.get("actor"),
        "vulnerability_class": record.get("vulnerability_class"),
        "headers": redact_headers(record.get("headers") or {}),
        "body": redact_value(record.get("body"), key="body"),
    }


def redact_response_record(record: dict[str, Any], *, max_body_chars: int = 4000) -> dict[str, Any]:
    body = record.get("body")
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    if isinstance(body, str) and len(body) > max_body_chars:
        body = f"{body[:max_body_chars]}[TRUNCATED]"
    return {
        "status": record.get("status"),
        "headers": redact_headers(record.get("headers") or {}),
        "body": redact_value(body, key="body"),
        "body_truncated": isinstance(record.get("body"), str)
        and len(str(record.get("body"))) > max_body_chars,
    }


def evidence_record(
    *,
    request: dict[str, Any],
    response: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "request_id": request.get("request_id"),
        "endpoint_id": request.get("endpoint_id"),
        "fuzz_id": request.get("fuzz_id"),
        "actor": request.get("actor"),
        "vulnerability_class": request.get("vulnerability_class"),
        "request": redact_request_record(request),
    }
    if response is not None:
        output["response"] = redact_response_record(response)
    if decision is not None:
        output["scope_decision"] = decision
    if error:
        output["error"] = error
    return output
