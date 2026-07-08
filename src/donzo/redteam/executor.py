from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from donzo.models import stable_id
from donzo.redteam.actor_sessions import ActorSessionManager
from donzo.redteam.evidence import evidence_record
from donzo.redteam.scope_guard import RedteamScopeGuard

Transport = Callable[[dict[str, Any]], dict[str, Any]]


class RedteamHTTPExecutor:
    def __init__(
        self,
        guard: RedteamScopeGuard,
        actor_sessions: ActorSessionManager,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.guard = guard
        self.actor_sessions = actor_sessions
        self.transport = transport or urllib_transport
        self._last_request_at = 0.0

    def execute_requests(
        self,
        requests: list[dict[str, Any]],
        *,
        mode: str,
        execute: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        baseline_results: list[dict[str, Any]] = []
        probe_results: list[dict[str, Any]] = []
        readback_results: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        for raw_request in requests:
            request = normalize_request(raw_request)
            class_reasons = self.actor_sessions.validate_for_class(
                str(request.get("vulnerability_class") or "")
            )
            decision = self.guard.evaluate_request(
                request,
                mode=mode,
                actors_present=self.actor_sessions.has_actors,
            )
            reasons = decision.reasons + class_reasons
            if reasons or not execute:
                status = "blocked_by_scope" if reasons else "not_executed"
                record = {
                    **decision.to_dict(),
                    "allowed": not reasons,
                    "status": status,
                    "reasons": reasons or ["execute_flag_required"],
                }
                blocked.append(record)
                evidence.append(evidence_record(request=request, decision=record))
                continue

            self._pace()
            try:
                response = self.transport(request)
                status_code = as_int(response.get("status"))
                endpoint_id = str(
                    request.get("endpoint_id") or f"{request['method']} {request['url']}"
                )
                self.guard.record_result(endpoint_id, status_code)
                result = {
                    "request_id": request["request_id"],
                    "fuzz_id": request.get("fuzz_id"),
                    "endpoint_id": endpoint_id,
                    "actor": request.get("actor"),
                    "vulnerability_class": request.get("vulnerability_class"),
                    "probe_role": request.get("probe_role") or "probe",
                    "status": status_code,
                    "headers": response.get("headers") or {},
                    "body": response.get("body"),
                    "timing_ms": response.get("timing_ms"),
                }
                append_result(result, baseline_results, probe_results, readback_results)
                evidence.append(evidence_record(request=request, response=response))
            except Exception as exc:  # noqa: BLE001 - executor records transport errors as artifacts.
                error_record = {
                    "request_id": request["request_id"],
                    "endpoint_id": request.get("endpoint_id"),
                    "status": "transport_error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
                blocked.append(error_record)
                evidence.append(evidence_record(request=request, error=error_record["error"]))

        return {
            "baseline_results": baseline_results,
            "probe_results": probe_results,
            "readback_results": readback_results,
            "blocked_requests": blocked,
            "evidence": evidence,
        }

    def _pace(self) -> None:
        max_rps = self.guard.limits.max_rps
        if max_rps <= 0:
            return
        interval = 1.0 / max_rps
        now = time.monotonic()
        wait = self._last_request_at + interval - now
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()


def execute_redteam_requests(
    requests: list[dict[str, Any]],
    *,
    guard: RedteamScopeGuard,
    actor_sessions: ActorSessionManager,
    mode: str,
    execute: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    return RedteamHTTPExecutor(guard, actor_sessions).execute_requests(
        requests,
        mode=mode,
        execute=execute,
    )


def normalize_request(record: dict[str, Any]) -> dict[str, Any]:
    method = str(record.get("method") or "GET").upper()
    url = str(record.get("url") or record.get("target") or "")
    vulnerability_class = str(
        record.get("vulnerability_class") or record.get("class") or ""
    ).upper()
    request_id = str(
        record.get("request_id")
        or stable_id("redteam_request", method, url, vulnerability_class, record.get("actor"))
    )
    normalized = {
        **record,
        "request_id": request_id,
        "method": method,
        "url": url,
        "vulnerability_class": vulnerability_class,
        "headers": record.get("headers") or {},
    }
    return normalized


def urllib_transport(request_record: dict[str, Any]) -> dict[str, Any]:
    body = request_record.get("body")
    data: bytes | None
    if body in (None, ""):
        data = None
    elif isinstance(body, bytes):
        data = body
    elif isinstance(body, dict | list):
        data = json.dumps(body, sort_keys=True).encode("utf-8")
    else:
        data = str(body).encode("utf-8")
    headers = {str(key): str(value) for key, value in (request_record.get("headers") or {}).items()}
    req = urllib.request.Request(
        str(request_record["url"]),
        data=data,
        headers=headers,
        method=str(request_record.get("method") or "GET").upper(),
    )
    started = time.monotonic()
    try:
        timeout = float(request_record.get("timeout_seconds") or 10)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(int(request_record.get("max_body_bytes") or 200_000))
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": raw.decode("utf-8", errors="replace"),
                "timing_ms": round((time.monotonic() - started) * 1000, 3),
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read(int(request_record.get("max_body_bytes") or 200_000))
        return {
            "status": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body": raw.decode("utf-8", errors="replace"),
            "timing_ms": round((time.monotonic() - started) * 1000, 3),
        }


def append_result(
    result: dict[str, Any],
    baseline_results: list[dict[str, Any]],
    probe_results: list[dict[str, Any]],
    readback_results: list[dict[str, Any]],
) -> None:
    role = str(result.get("probe_role") or "").lower()
    if "baseline" in role:
        baseline_results.append(result)
    elif "read" in role:
        readback_results.append(result)
    else:
        probe_results.append(result)


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
