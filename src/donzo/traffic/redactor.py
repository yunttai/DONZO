from __future__ import annotations

import re
from typing import Any

SECRET_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}
SECRET_KEY_MARKERS = (
    "authorization",
    "cookie",
    "secret",
    "token",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "session",
    "credential",
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
LONG_SECRET_RE = re.compile(r"\b[A-Za-z0-9_=-]{32,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in sorted(headers.items(), key=lambda item: item[0].lower()):
        normalized = key.lower()
        if normalized in SECRET_HEADER_NAMES:
            output[normalized] = "[REDACTED]"
        else:
            output[normalized] = redact_string(str(value))
    return output


def has_auth_material(headers: dict[str, str]) -> bool:
    lowered = {key.lower(): value for key, value in headers.items()}
    return any(name in lowered and bool(str(lowered[name]).strip()) for name in SECRET_HEADER_NAMES)


def redact_value(value: Any, *, key: str = "") -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        if is_secret_key(key):
            return "[REDACTED]"
        return redact_string(value)
    if isinstance(value, list):
        return [redact_value(item, key=key) for item in value[:50]]
    if isinstance(value, dict):
        return {
            str(item_key): redact_value(item_value, key=str(item_key))
            for item_key, item_value in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    return "[UNSUPPORTED]"


def redact_string(value: str) -> str:
    redacted = JWT_RE.sub("[REDACTED_TOKEN]", value)
    redacted = EMAIL_RE.sub("[EMAIL]", redacted)
    redacted = CARD_RE.sub("[PAYMENT_CARD]", redacted)
    redacted = PHONE_RE.sub("[PHONE]", redacted)
    redacted = LONG_SECRET_RE.sub("[REDACTED_SECRET]", redacted)
    return redacted


def is_secret_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return any(marker in normalized for marker in SECRET_KEY_MARKERS)
