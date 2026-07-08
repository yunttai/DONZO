from __future__ import annotations

import os
from urllib.parse import urlparse

from donzo.config import ScopeConfig
from donzo.scope import domain_matches, normalize_host

REDACTED_VALUE = "[REDACTED]"


def auth_headers_for_url(url: str, *, config: ScopeConfig) -> list[str]:
    auth = config.authenticated_crawl
    if not auth.enabled or not auth.pass_to_probes:
        return []
    if not auth_allowed_for_url(url, config=config):
        return []
    return configured_auth_headers(config)


def auth_tool_header_args(
    urls: list[str],
    *,
    config: ScopeConfig,
) -> tuple[list[str], list[str], dict[str, object]]:
    auth = config.authenticated_crawl
    summary = auth_summary(config)
    if not auth.enabled or not auth.pass_to_tools:
        return [], [], summary
    if not any(auth_allowed_for_url(url, config=config) for url in urls):
        summary["enabled_for_targets"] = False
        return [], [], summary
    headers = configured_auth_headers(config)
    if not headers:
        return [], [], summary
    argv: list[str] = []
    redacted_argv: list[str] = []
    for header in headers:
        argv.extend(["-H", header])
        redacted_argv.extend(["-H", redact_header(header)])
    summary["header_count"] = len(headers)
    summary["enabled_for_targets"] = True
    return argv, redacted_argv, summary


def configured_auth_headers(config: ScopeConfig) -> list[str]:
    auth = config.authenticated_crawl
    if not auth.enabled:
        return []
    headers: list[str] = []
    if auth.header_env:
        value = os.environ.get(auth.header_env, "")
        header = normalize_header_value(value, default_name="Authorization")
        if header:
            headers.append(header)
    if auth.cookie_env:
        value = os.environ.get(auth.cookie_env, "")
        header = normalize_header_value(value, default_name="Cookie")
        if header:
            headers.append(header)
    return headers


def normalize_header_value(value: str, *, default_name: str) -> str:
    normalized = " ".join(str(value or "").splitlines()).strip()
    if not normalized:
        return ""
    if ":" in normalized:
        name, raw_value = normalized.split(":", 1)
        name = name.strip()
        raw_value = raw_value.strip()
    else:
        name = default_name
        raw_value = normalized
    if not name or not raw_value:
        return ""
    return f"{name}: {raw_value}"


def auth_allowed_for_url(url: str, *, config: ScopeConfig) -> bool:
    parsed = urlparse(url)
    host = normalize_host(parsed.hostname or "")
    if not host:
        return False
    if not config.scope.decide(url).allowed:
        return False
    allowed_domains = config.authenticated_crawl.allowed_domains
    if not allowed_domains:
        return True
    return any(domain_matches(host, rule) for rule in allowed_domains)


def redact_header(header: str) -> str:
    if ":" not in header:
        return REDACTED_VALUE
    name, _value = header.split(":", 1)
    return f"{name.strip()}: {REDACTED_VALUE}"


def auth_summary(config: ScopeConfig) -> dict[str, object]:
    auth = config.authenticated_crawl
    return {
        "enabled": auth.enabled,
        "header_env_configured": bool(auth.header_env),
        "cookie_env_configured": bool(auth.cookie_env),
        "header_env_present": bool(auth.header_env and os.environ.get(auth.header_env)),
        "cookie_env_present": bool(auth.cookie_env and os.environ.get(auth.cookie_env)),
        "allowed_domains": list(auth.allowed_domains),
        "pass_to_tools": auth.pass_to_tools,
        "pass_to_probes": auth.pass_to_probes,
        "header_count": len(configured_auth_headers(config)),
        "enabled_for_targets": False,
    }
