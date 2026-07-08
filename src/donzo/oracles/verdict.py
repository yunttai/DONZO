from __future__ import annotations

from typing import Any

from donzo.fuzzing.models import FUZZ_VERDICT_STATUSES


def oracle_verdict(
    status: str,
    confidence: float,
    reason: str,
    severity_hint: str = "info",
    *,
    evidence: list[str] | None = None,
    needs_more_evidence: list[str] | None = None,
    false_positive_reasons: list[str] | None = None,
) -> dict[str, Any]:
    normalized = status if status in FUZZ_VERDICT_STATUSES else "needs_more_evidence"
    return {
        "status": normalized,
        "confidence": max(0.0, min(1.0, float(confidence))),
        "reason": reason,
        "severity_hint": severity_hint,
        "evidence": evidence or [],
        "needs_more_evidence": needs_more_evidence or [],
        "false_positive_reasons": false_positive_reasons or [],
    }


def first_present(record: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for key in keys:
        if record.get(key) not in (None, "", [], {}):
            return record.get(key)
    return default


def coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "confirmed", "server_side"}
    return bool(value)


def coerce_status(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_success(value: Any) -> bool:
    status = coerce_status(value)
    return status is not None and 200 <= status < 300


def is_denied(value: Any) -> bool:
    return coerce_status(value) in {401, 403, 404}
