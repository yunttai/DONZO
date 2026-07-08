from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from donzo.config import ScopeConfig
from donzo.models import stable_id
from donzo.verification.probe import (
    ProbeResult,
    failed_probe,
    origin_url,
    probe_from_record,
    probe_url,
)

API_DOC_JSON_KEYS = {"openapi", "swagger", "paths", "components", "schemas", "securitySchemes"}
API_DOC_HTML_PATTERNS = {
    "swagger ui": "swagger_ui",
    "swagger-ui": "swagger_ui",
    "redoc": "redoc",
    "openapi.json": "openapi_schema_ref",
    "swagger.json": "swagger_schema_ref",
    "v3/api-docs": "openapi_schema_ref",
}
GRAPHQL_PATTERNS = {
    "must provide query string": "missing_query_error",
    "graphql": "graphql_keyword",
    "cannot query field": "graphql_error",
    "graphql playground": "graphql_playground",
    "graphiql": "graphiql",
    "apollo": "apollo",
}
AUTH_ENDPOINT_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "registration",
    "logout",
    "auth",
    "oauth",
    "callback",
    "saml",
    "sso",
    "token",
    "session",
    "password",
    "reset-password",
    "forgot-password",
    "verify-email",
    "email-verification",
    "mfa",
    "otp",
    "captcha",
}
RESOURCE_KEYWORDS = {
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "order",
    "orders",
    "invoice",
    "invoices",
    "document",
    "documents",
    "file",
    "files",
    "attachment",
    "attachments",
    "project",
    "projects",
    "team",
    "teams",
    "organization",
    "organizations",
    "tenant",
    "tenants",
    "ticket",
    "tickets",
    "report",
    "reports",
    "address",
    "addresses",
    "payment_method",
    "payment_methods",
}
NOT_OBJECT_ID_PARAMS = {
    "client_id",
    "state",
    "code",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "csrf",
    "captcha",
    "redirect_uri",
    "returnurl",
    "next",
}
ERROR_TEXT_MARKERS = {
    "not found",
    "page not found",
    "404",
    "does not exist",
    "no such page",
    "error page",
}
FILTER_REASON_CATEGORIES = {
    "auth_endpoint_not_bola": "auth_flow_false_positive",
    "missing_object_id": "weak_object_access_evidence",
    "not_object_resource": "weak_object_access_evidence",
    "not_actual_api_doc": "api_doc_false_positive",
    "not_actual_sourcemap": "sourcemap_false_positive",
    "not_graphql": "graphql_false_positive",
    "soft_404_common_error": "soft_404",
    "login_redirect_only": "redirect_noise",
    "redirect_only": "redirect_noise",
    "redirect_final_url_out_of_scope": "scope_or_redirect",
    "out_of_scope": "scope_or_redirect",
    "missing_target": "malformed_candidate",
}
LOGIN_REDIRECT_PATHS = {"/login", "/signin", "/sign-in", "/auth/login", "/accounts/login"}
HOME_REDIRECT_PATHS = {"/", "/error", "/404", "/not-found"}


@dataclass(frozen=True)
class VerificationResult:
    candidates: list[dict[str, Any]]
    filtered: list[dict[str, Any]]
    probes: list[dict[str, Any]]
    soft404_baselines: list[dict[str, Any]]
    summary: dict[str, Any]


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self.last_call = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        now = time.monotonic()
        elapsed = now - self.last_call
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_call = time.monotonic()


@dataclass
class NetworkProbeBudget:
    limit: int
    used: int = 0

    def consume(self) -> bool:
        if self.unlimited:
            self.used += 1
            return True
        if self.used >= self.limit:
            return False
        self.used += 1
        return True

    @property
    def unlimited(self) -> bool:
        return self.limit <= 0

    @property
    def exhausted(self) -> bool:
        return False if self.unlimited else self.used >= self.limit


@dataclass
class OriginTimeoutCache:
    threshold: int = 2
    failures: dict[str, int] = field(default_factory=dict)
    skipped: int = 0

    def should_skip(self, origin: str) -> bool:
        return self.threshold > 0 and self.failures.get(origin, 0) >= self.threshold

    def record_probe(self, origin: str, probe: ProbeResult) -> None:
        if is_timeout_signature(probe.error_signature):
            self.failures[origin] = self.failures.get(origin, 0) + 1
            return
        if probe.status_code is not None:
            self.failures.pop(origin, None)

    def record_skip(self) -> None:
        self.skipped += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "origins": dict(sorted(self.failures.items())),
            "origin_count": len(self.failures),
            "skipped_probes": self.skipped,
        }


ProgressCallback = Callable[[dict[str, Any]], None]


def verify_candidates(
    candidates: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    endpoints: list[dict[str, Any]] | None = None,
    network: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> VerificationResult:
    if not config.verification.enabled:
        kept = [
            mark_unverified(candidate, reason="verification_disabled") for candidate in candidates
        ]
        return build_result(kept, [], [], [], enabled=False)

    endpoint_index = {str(item.get("url") or ""): item for item in endpoints or []}
    probes_by_url: dict[str, ProbeResult] = {}
    soft404_by_origin: dict[str, ProbeResult] = {}
    limiter = RateLimiter(config.rate_limit.max_requests_per_second)
    network_budget = NetworkProbeBudget(config.verification.probe.max_network_probes)
    timeout_cache = OriginTimeoutCache(origin_timeout_threshold(config))
    kept: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    total = len(candidates)
    progress_interval = max(1, total // 100) if total else 1
    emit_verification_progress(
        progress_callback,
        processed=0,
        total=total,
        kept=kept,
        filtered=filtered,
        budget=network_budget,
        timeout_cache=timeout_cache,
        force=True,
    )

    for index, candidate in enumerate(candidates, start=1):
        target = str(candidate.get("target") or candidate.get("url") or "")
        if not target:
            filtered.append(filter_candidate(candidate, "missing_target"))
            emit_verification_progress(
                progress_callback,
                processed=index,
                total=total,
                kept=kept,
                filtered=filtered,
                budget=network_budget,
                timeout_cache=timeout_cache,
                force=index == total or index % progress_interval == 0,
            )
            continue
        scope_decision = config.scope.decide(target)
        if not scope_decision.allowed:
            filtered.append(
                filter_candidate(
                    candidate,
                    "out_of_scope",
                    details={"scope_reasons": scope_decision.reasons},
                )
            )
            emit_verification_progress(
                progress_callback,
                processed=index,
                total=total,
                kept=kept,
                filtered=filtered,
                budget=network_budget,
                timeout_cache=timeout_cache,
                force=index == total or index % progress_interval == 0,
            )
            continue

        endpoint = endpoint_index.get(target)
        probe = resolve_probe(
            target,
            candidate=candidate,
            endpoint=endpoint,
            config=config,
            network=network,
            probes_by_url=probes_by_url,
            limiter=limiter,
            budget=network_budget,
            timeout_cache=timeout_cache,
        )
        baseline = resolve_soft404_baseline(
            target,
            config=config,
            network=network and probe is not None,
            baselines=soft404_by_origin,
            limiter=limiter,
            budget=network_budget,
            timeout_cache=timeout_cache,
        )
        verified = verify_one_candidate(
            candidate,
            config=config,
            endpoint=endpoint,
            probe=probe,
            baseline=baseline,
            network=network,
        )
        if str(verified.get("verification_status")) == "filtered_out":
            filtered.append(verified)
        else:
            kept.append(verified)
        emit_verification_progress(
            progress_callback,
            processed=index,
            total=total,
            kept=kept,
            filtered=filtered,
            budget=network_budget,
            timeout_cache=timeout_cache,
            force=index == total or index % progress_interval == 0,
        )

    probes = [probe.to_dict() for probe in probes_by_url.values()]
    baselines = [probe.to_dict() for probe in soft404_by_origin.values()]
    return build_result(
        kept,
        filtered,
        probes,
        baselines,
        enabled=True,
        network_probe_budget={
            "limit": network_budget.limit,
            "unlimited": network_budget.unlimited,
            "used": network_budget.used,
            "exhausted": network_budget.exhausted,
        },
        origin_timeout_cache=timeout_cache.to_dict(),
    )


def resolve_probe(
    target: str,
    *,
    candidate: dict[str, Any],
    endpoint: dict[str, Any] | None,
    config: ScopeConfig,
    network: bool,
    probes_by_url: dict[str, ProbeResult],
    limiter: RateLimiter,
    budget: NetworkProbeBudget,
    timeout_cache: OriginTimeoutCache,
) -> ProbeResult | None:
    if target in probes_by_url:
        return probes_by_url[target]
    if endpoint and (metadata_probe := probe_from_record(endpoint)):
        probes_by_url[target] = metadata_probe
        if not network or (
            metadata_probe.status_code is not None and not candidate_requires_body(candidate)
        ):
            return metadata_probe
    if not network or not config.verification.network_probe:
        return probes_by_url.get(target)
    origin = origin_url(target)
    method = probe_method(candidate)
    if timeout_cache.should_skip(origin):
        timeout_cache.record_skip()
        probe = failed_probe(
            target,
            method,
            final_url=target,
            error_signature="origin_timeout_cached",
        )
        probes_by_url[target] = probe
        return probe
    if not budget.consume():
        probe = failed_probe(
            target,
            method,
            final_url=target,
            error_signature="probe_budget_exhausted",
        )
        probes_by_url[target] = probe
        return probe
    limiter.wait()
    probe = probe_url(target, config=config, method=method)
    probes_by_url[target] = probe
    timeout_cache.record_probe(origin, probe)
    return probe


def probe_method(candidate: dict[str, Any]) -> str:
    candidate_type = str(candidate.get("candidate_type") or "").upper()
    if candidate_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER", "GRAPHQL", "SOURCE_MAP_EXPOSURE"}:
        return "GET"
    return "GET"


def candidate_requires_body(candidate: dict[str, Any]) -> bool:
    candidate_type = str(candidate.get("candidate_type") or "").upper()
    return candidate_type in {
        "EXPOSED_API_DOCS",
        "PUBLIC_SWAGGER",
        "GRAPHQL",
        "GRAPHQL_ENDPOINT",
        "GRAPHQL_INTROSPECTION",
        "SOURCE_MAP_EXPOSURE",
    }


def resolve_soft404_baseline(
    target: str,
    *,
    config: ScopeConfig,
    network: bool,
    baselines: dict[str, ProbeResult],
    limiter: RateLimiter,
    budget: NetworkProbeBudget,
    timeout_cache: OriginTimeoutCache,
) -> ProbeResult | None:
    if not network or not config.verification.soft404.enabled:
        return None
    origin = origin_url(target)
    if origin in baselines:
        return baselines[origin]
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return None
    baseline_path = f"/__donzo_probe_{stable_id('soft404', parsed.netloc)}__"
    baseline_url = urlunparse((parsed.scheme, parsed.netloc, baseline_path, "", "", ""))
    if not config.scope.decide(baseline_url).allowed:
        return None
    if timeout_cache.should_skip(origin):
        timeout_cache.record_skip()
        baseline = failed_probe(
            baseline_url,
            "GET",
            final_url=baseline_url,
            error_signature="origin_timeout_cached",
        )
        baselines[origin] = baseline
        return baseline
    if not budget.consume():
        return None
    limiter.wait()
    baseline = probe_url(baseline_url, config=config, method="GET")
    baselines[origin] = baseline
    timeout_cache.record_probe(origin, baseline)
    return baseline


def emit_verification_progress(
    callback: ProgressCallback | None,
    *,
    processed: int,
    total: int,
    kept: list[dict[str, Any]],
    filtered: list[dict[str, Any]],
    budget: NetworkProbeBudget,
    timeout_cache: OriginTimeoutCache,
    force: bool = False,
) -> None:
    if not callback or not force:
        return
    percent = 100 if total <= 0 else round(processed * 100 / total)
    callback(
        {
            "event": "verification_progress",
            "processed": processed,
            "total": total,
            "percent": max(0, min(100, percent)),
            "reviewable": len(kept),
            "filtered": len(filtered),
            "probe_limit": budget.limit,
            "probe_used": budget.used,
            "probe_exhausted": budget.exhausted,
            "origin_timeout_cached": timeout_cache.skipped,
            "origin_timeout_count": len(timeout_cache.failures),
        }
    )


def origin_timeout_threshold(config: ScopeConfig) -> int:
    value = os.environ.get("DONZO_ORIGIN_TIMEOUT_THRESHOLD", "").strip()
    if not value:
        return config.verification.probe.origin_timeout_threshold
    try:
        parsed = int(value)
    except ValueError:
        return config.verification.probe.origin_timeout_threshold
    return max(0, min(10, parsed))


def is_timeout_signature(value: str | None) -> bool:
    signature = str(value or "").lower()
    return signature == "timeout" or "timeout" in signature


def verify_one_candidate(
    candidate: dict[str, Any],
    *,
    config: ScopeConfig,
    endpoint: dict[str, Any] | None,
    probe: ProbeResult | None,
    baseline: ProbeResult | None,
    network: bool,
) -> dict[str, Any]:
    candidate_type = str(candidate.get("candidate_type") or "").upper()

    if candidate_type in {"BOLA_IDOR", "IDOR"}:
        bola_result = verify_bola_candidate(candidate, config=config, endpoint=endpoint)
        if str(bola_result.get("verification_status")) == "filtered_out":
            return bola_result

    redirect_reason = redirect_filter_reason(candidate, probe, config=config)
    if redirect_reason:
        return filter_candidate(candidate, redirect_reason, probe=probe)

    if is_soft404(probe, baseline, config=config):
        return filter_candidate(candidate, "soft_404_common_error", probe=probe)

    if candidate_type in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER"}:
        return verify_api_docs_candidate(candidate, config=config, probe=probe, network=network)
    if candidate_type == "SOURCE_MAP_EXPOSURE":
        return verify_source_map_candidate(candidate, config=config, probe=probe, network=network)
    if candidate_type in {"GRAPHQL", "GRAPHQL_ENDPOINT", "GRAPHQL_INTROSPECTION"}:
        return verify_graphql_candidate(candidate, config=config, probe=probe, network=network)

    if probe and probe.status_code is not None:
        return enrich_candidate(
            candidate,
            "needs_manual_review",
            method="http_probe",
            probe=probe,
            details={"status_code": probe.status_code},
        )
    return mark_unverified(candidate, reason="no_probe_available")


def verify_api_docs_candidate(
    candidate: dict[str, Any],
    *,
    config: ScopeConfig,
    probe: ProbeResult | None,
    network: bool,
) -> dict[str, Any]:
    if not config.verification.api_docs.enabled:
        return mark_unverified(candidate, reason="api_docs_verifier_disabled", probe=probe)
    if not probe:
        return no_probe_verdict(candidate, "not_actual_api_doc", network=network, config=config)
    if reason := indeterminate_probe_reason(probe):
        return mark_unverified(
            candidate,
            reason=reason,
            probe=probe,
            include_in_final_report=False,
        )
    if not status_is_success(probe):
        return filter_candidate(candidate, "not_actual_api_doc", probe=probe)
    if not final_url_in_scope(probe, config):
        return filter_candidate(candidate, "redirect_final_url_out_of_scope", probe=probe)
    text = probe.body_text
    if not text and not network:
        return mark_unverified(candidate, reason="metadata_only_no_body", probe=probe)
    doc_summary = api_doc_summary(text, probe.content_type, config=config)
    if not doc_summary["is_actual_api_doc"]:
        return filter_candidate(candidate, "not_actual_api_doc", probe=probe, details=doc_summary)
    confidence = max(float(candidate.get("confidence") or 0), 0.75)
    output = enrich_candidate(
        {**candidate, "confidence": confidence},
        "verified",
        method="api_docs_fingerprint",
        probe=probe,
        details=doc_summary,
    )
    output["reason"] = append_unique(output.get("reason"), "API documentation fingerprint verified")
    return output


def api_doc_summary(text: str, content_type: str, *, config: ScopeConfig) -> dict[str, Any]:
    lowered = text.lower()
    content_type_l = content_type.lower()
    matched_patterns: list[str] = []
    doc_type = ""
    schema_urls = extract_schema_urls(text)
    api_path_count = 0
    sensitive_path_hints: list[str] = []
    schema_verified = False

    parsed = parse_json_object(text)
    if parsed is not None:
        keys = set(parsed)
        matched_patterns = sorted(keys & API_DOC_JSON_KEYS)
        paths = parsed.get("paths")
        if isinstance(paths, dict):
            api_path_count = len(paths)
            sensitive_path_hints = sensitive_paths(
                list(paths),
                config.verification.api_docs.sensitive_path_keywords,
            )
        schema_verified = bool({"openapi", "swagger", "paths"} & keys)
        if parsed.get("openapi"):
            doc_type = "openapi_json"
        elif parsed.get("swagger"):
            doc_type = "swagger_json"
        elif matched_patterns:
            doc_type = "api_json"

    if not doc_type and ("html" in content_type_l or "<html" in lowered):
        for pattern, label in API_DOC_HTML_PATTERNS.items():
            if pattern in lowered:
                matched_patterns.append(pattern)
                doc_type = label
        schema_verified = bool(schema_urls)

    is_actual = bool(doc_type and (matched_patterns or schema_verified))
    return {
        "is_actual_api_doc": is_actual,
        "doc_type": doc_type,
        "schema_urls": schema_urls[:5],
        "schema_verified": schema_verified,
        "api_path_count": api_path_count,
        "sensitive_path_hints": sensitive_path_hints[:10],
        "matched_patterns": sorted(set(matched_patterns)),
    }


def verify_source_map_candidate(
    candidate: dict[str, Any],
    *,
    config: ScopeConfig,
    probe: ProbeResult | None,
    network: bool,
) -> dict[str, Any]:
    if not config.verification.sourcemap.enabled:
        return mark_unverified(candidate, reason="sourcemap_verifier_disabled", probe=probe)
    if not probe:
        return no_probe_verdict(candidate, "not_actual_sourcemap", network=network, config=config)
    if reason := indeterminate_probe_reason(probe):
        return mark_unverified(
            candidate,
            reason=reason,
            probe=probe,
            include_in_final_report=False,
        )
    if not status_is_success(probe):
        return filter_candidate(candidate, "not_actual_sourcemap", probe=probe)
    if not probe.body_text and not network:
        return mark_unverified(candidate, reason="metadata_only_no_body", probe=probe)
    parsed = parse_json_object(probe.body_text)
    if not isinstance(parsed, dict):
        return filter_candidate(candidate, "not_actual_sourcemap", probe=probe)
    sources = parsed.get("sources")
    has_required = parsed.get("version") and isinstance(sources, list) and parsed.get("mappings")
    if not has_required:
        return filter_candidate(candidate, "not_actual_sourcemap", probe=probe)
    sources_content = parsed.get("sourcesContent")
    details = {
        "is_actual_sourcemap": True,
        "map_version": parsed.get("version"),
        "sources_count": len(sources),
        "has_sources_content": isinstance(sources_content, list) and bool(sources_content),
        "file_field": parsed.get("file"),
        "source_samples": [str(item) for item in sources[:10]],
        "store_full_map": config.verification.sourcemap.store_full_map,
        "store_sources_content": config.verification.sourcemap.store_sources_content,
    }
    confidence = max(float(candidate.get("confidence") or 0), 0.65)
    output = enrich_candidate(
        {**candidate, "confidence": confidence},
        "verified",
        method="sourcemap_json_parse",
        probe=probe,
        details=details,
    )
    output["reason"] = append_unique(output.get("reason"), "Source map JSON structure verified")
    return output


def verify_graphql_candidate(
    candidate: dict[str, Any],
    *,
    config: ScopeConfig,
    probe: ProbeResult | None,
    network: bool,
) -> dict[str, Any]:
    if not config.verification.graphql.enabled:
        return mark_unverified(candidate, reason="graphql_verifier_disabled", probe=probe)
    if not probe:
        return no_probe_verdict(candidate, "not_graphql", network=network, config=config)
    if reason := indeterminate_probe_reason(probe):
        return mark_unverified(
            candidate,
            reason=reason,
            probe=probe,
            include_in_final_report=False,
        )
    if probe.status_code in {404, 410}:
        return filter_candidate(candidate, "not_graphql", probe=probe)
    if not probe.body_text and not network:
        return mark_unverified(candidate, reason="metadata_only_no_body", probe=probe)
    lowered = probe.body_text.lower()
    matched = [label for pattern, label in GRAPHQL_PATTERNS.items() if pattern in lowered]
    json_body = parse_json_object(probe.body_text)
    if isinstance(json_body, dict) and ("errors" in json_body or "data" in json_body):
        matched.append("graphql_json_shape")
    if not matched:
        return filter_candidate(candidate, "not_graphql", probe=probe)
    details = {
        "is_actual_graphql": True,
        "fingerprint_method": "GET_ERROR_FINGERPRINT",
        "matched_patterns": sorted(set(matched)),
        "safe_query_tested": False,
        "introspection_tested": False,
        "introspection_allowed": config.verification.graphql.introspection_test,
    }
    confidence = max(float(candidate.get("confidence") or 0), 0.70)
    output = enrich_candidate(
        {**candidate, "confidence": confidence},
        "verified",
        method="graphql_fingerprint",
        probe=probe,
        details=details,
    )
    output["reason"] = append_unique(output.get("reason"), "GraphQL fingerprint verified")
    return output


def verify_bola_candidate(
    candidate: dict[str, Any],
    *,
    config: ScopeConfig,
    endpoint: dict[str, Any] | None,
) -> dict[str, Any]:
    if not config.verification.bola_filter.enabled:
        return mark_unverified(candidate, reason="bola_filter_disabled")
    target = str(candidate.get("target") or "")
    parsed = urlparse(target)
    path_parts = [part.lower() for part in parsed.path.split("/") if part]
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_names = {name.lower() for name, _value in query_pairs}
    auth_keywords = sorted(set(path_parts) & AUTH_ENDPOINT_KEYWORDS)
    if not auth_keywords:
        auth_keywords = sorted(
            keyword
            for keyword in AUTH_ENDPOINT_KEYWORDS
            if any(keyword in part for part in path_parts)
        )
    resource_found = has_resource_keyword(path_parts, query_names)
    object_id_found = has_object_identifier(path_parts, query_pairs, endpoint)
    if config.verification.bola_filter.filter_auth_endpoints and auth_keywords:
        return filter_candidate(
            candidate,
            "auth_endpoint_not_bola",
            details={
                "matched_auth_keywords": auth_keywords,
                "object_resource_keyword_found": resource_found,
                "object_id_found": object_id_found,
            },
        )
    if config.verification.bola_filter.require_resource_keyword and not resource_found:
        return filter_candidate(candidate, "not_object_resource")
    if config.verification.bola_filter.require_object_id and not object_id_found:
        return filter_candidate(candidate, "missing_object_id")
    return enrich_candidate(
        candidate,
        "needs_manual_review",
        method="bola_false_positive_filter",
        details={
            "object_resource_keyword_found": resource_found,
            "object_id_found": object_id_found,
            "automatic_cross_account_test_performed": False,
        },
    )


def redirect_filter_reason(
    candidate: dict[str, Any],
    probe: ProbeResult | None,
    *,
    config: ScopeConfig,
) -> str:
    if not probe or not config.verification.redirect_filter.enabled:
        return ""
    candidate_type = str(candidate.get("candidate_type") or "").upper()
    if (
        candidate_type == "OPEN_REDIRECT"
        and config.verification.redirect_filter.keep_for_open_redirect_candidates
    ):
        return ""
    if not probe.redirect_chain:
        return ""
    parsed = urlparse(probe.final_url)
    path = parsed.path.rstrip("/") or "/"
    if config.verification.redirect_filter.filter_login_redirects and path in LOGIN_REDIRECT_PATHS:
        return "login_redirect_only"
    if config.verification.redirect_filter.filter_home_redirects and path in HOME_REDIRECT_PATHS:
        return "redirect_only"
    return ""


def is_soft404(
    probe: ProbeResult | None,
    baseline: ProbeResult | None,
    *,
    config: ScopeConfig,
) -> bool:
    if not probe or not config.verification.soft404.enabled:
        return False
    if probe.status_code not in {200, 404}:
        return False
    text = f"{probe.title}\n{probe.body_text}".lower()
    if probe.status_code == 200 and any(marker in text for marker in ERROR_TEXT_MARKERS):
        return True
    if not baseline or not baseline.body_sha256 or not probe.body_sha256:
        return False
    if probe.body_sha256 == baseline.body_sha256:
        return True
    if not probe.content_length or not baseline.content_length:
        return False
    tolerance = config.verification.soft404.content_length_tolerance_ratio
    delta = abs(probe.content_length - baseline.content_length)
    similar_length = delta <= max(64, int(baseline.content_length * tolerance))
    same_title = bool(probe.title and probe.title == baseline.title)
    return similar_length and same_title and probe.status_code == baseline.status_code


def no_probe_verdict(
    candidate: dict[str, Any],
    filter_reason: str,
    *,
    network: bool,
    config: ScopeConfig,
) -> dict[str, Any]:
    if network and config.verification.fail_closed:
        return mark_unverified(
            candidate,
            reason="probe_not_completed",
            include_in_final_report=False,
        )
    return mark_unverified(candidate, reason="no_probe_available")


def indeterminate_probe_reason(probe: ProbeResult) -> str:
    if probe.status_code is not None:
        return ""
    signature = str(probe.error_signature or "").lower()
    if not signature:
        return "probe_no_response"
    if signature == "probe_budget_exhausted":
        return "probe_budget_exhausted"
    if signature == "origin_timeout_cached":
        return "origin_timeout_cached"
    if is_timeout_signature(signature):
        return "probe_timeout"
    if signature.startswith("network_error:"):
        return "probe_network_error"
    if signature.startswith("invalid_url:"):
        return "probe_invalid_url"
    return "probe_error"


def mark_unverified(
    candidate: dict[str, Any],
    *,
    reason: str,
    probe: ProbeResult | None = None,
    include_in_final_report: bool | None = None,
) -> dict[str, Any]:
    output = enrich_candidate(
        candidate,
        "needs_manual_review",
        method="metadata_only",
        probe=probe,
        details={"reason": reason},
    )
    if include_in_final_report is not None:
        output["include_in_final_report"] = include_in_final_report
    return output


def filter_candidate(
    candidate: dict[str, Any],
    reason: str,
    *,
    probe: ProbeResult | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output = enrich_candidate(
        candidate,
        "filtered_out",
        method="candidate_verification_filter",
        probe=probe,
        details=details or {},
    )
    output["filter_reason"] = reason
    output["filter_category"] = filter_reason_category(reason)
    output["include_in_final_report"] = False
    return output


def enrich_candidate(
    candidate: dict[str, Any],
    status: str,
    *,
    method: str,
    probe: ProbeResult | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output = dict(candidate)
    output["auto_exploit"] = False
    output["verification_status"] = status
    output["verification_method"] = method
    output["source"] = append_unique(output.get("source"), "candidate_verification")
    evidence = dict(output.get("evidence") if isinstance(output.get("evidence"), dict) else {})
    verification = {
        "status": status,
        "method": method,
        **(details or {}),
    }
    if probe:
        verification["probe_id"] = probe.probe_id
        verification["status_code"] = probe.status_code
        verification["final_url"] = probe.final_url
        verification["content_type"] = probe.content_type
        verification["title"] = probe.title
        verification["redirect_count"] = len(probe.redirect_chain)
        evidence["probe"] = probe.to_dict()
    evidence["verification"] = verification
    output["evidence"] = evidence
    return output


def build_result(
    kept: list[dict[str, Any]],
    filtered: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    baselines: list[dict[str, Any]],
    *,
    enabled: bool,
    network_probe_budget: dict[str, Any] | None = None,
    origin_timeout_cache: dict[str, Any] | None = None,
) -> VerificationResult:
    status_counts = Counter(str(item.get("verification_status") or "unknown") for item in kept)
    unverified_reason_counts = Counter(
        str(verification_reason(item) or "unknown")
        for item in kept
        if str(item.get("verification_status") or "") == "needs_manual_review"
    )
    filter_counts = Counter(str(item.get("filter_reason") or "unknown") for item in filtered)
    category_counts = Counter(
        str(item.get("filter_category") or filter_reason_category(item.get("filter_reason")))
        for item in filtered
    )
    summary = {
        "enabled": enabled,
        "input_candidates": len(kept) + len(filtered),
        "reviewable_candidates": len(kept),
        "filtered_candidates": len(filtered),
        "status_counts": dict(sorted(status_counts.items())),
        "unverified_reason_counts": dict(sorted(unverified_reason_counts.items())),
        "filter_reason_counts": dict(sorted(filter_counts.items())),
        "filter_category_counts": dict(sorted(category_counts.items())),
        "probe_count": len(probes),
        "soft404_baseline_count": len(baselines),
    }
    if network_probe_budget is not None:
        summary["network_probe_budget"] = network_probe_budget
    if origin_timeout_cache is not None:
        summary["origin_timeout_cache"] = origin_timeout_cache
    return VerificationResult(
        candidates=kept,
        filtered=filtered,
        probes=probes,
        soft404_baselines=baselines,
        summary=summary,
    )


def verification_reason(record: dict[str, Any]) -> str:
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    verification = (
        evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
    )
    return str(verification.get("reason") or "")


def filter_reason_category(reason: object) -> str:
    value = str(reason or "unknown")
    return FILTER_REASON_CATEGORIES.get(value, "other_false_positive")


def build_cluster_evidence_packs(
    clusters: list[dict[str, Any]],
    records: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    filtered: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    record_index = {
        str(item.get("finding_id") or item.get("candidate_id") or item.get("id") or ""): item
        for item in records
    }
    filtered_counts = Counter(
        str(item.get("filter_reason") or "unknown") for item in filtered or []
    )
    packs: list[dict[str, Any]] = []
    for cluster in clusters:
        record_ids = [str(item) for item in cluster.get("record_ids") or []]
        members = [record_index[item] for item in record_ids if item in record_index]
        if not members:
            cluster_targets = set(cluster.get("targets") or [])
            members = [
                item
                for item in records
                if str(item.get("target") or item.get("url") or "") in cluster_targets
            ]
        pack_id = stable_id("cluster_evidence_pack", cluster.get("cluster_id"), record_ids)
        packs.append(
            {
                "stage": "cluster_triage",
                "pack_id": pack_id,
                "program": config.program_name,
                "scope_file": str(config.source_path),
                "cluster": cluster,
                "candidate_count": len(members),
                "evidence_summary": summarize_members(members),
                "filtered_summary": dict(sorted(filtered_counts.items())),
                "safety_constraints": {
                    "automatic_exploit": False,
                    "destructive_testing": False,
                    "secret_validation": False,
                    "takeover_claim": False,
                },
                "task": (
                    "Decide whether this verified cluster should be prioritized for "
                    "manual verification. Do not claim exploitation."
                ),
            }
        )
    return packs


def summarize_members(records: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(item.get("verification_status") or "unknown") for item in records)
    types = Counter(str(item.get("candidate_type") or "unknown") for item in records)
    verified = [item for item in records if item.get("verification_status") == "verified"]
    representative = records[0] if records else {}
    evidence = (
        representative.get("evidence") if isinstance(representative.get("evidence"), dict) else {}
    )
    verification = (
        evidence.get("verification") if isinstance(evidence.get("verification"), dict) else {}
    )
    return {
        "verification_status_counts": dict(sorted(statuses.items())),
        "candidate_type_counts": dict(sorted(types.items())),
        "verified_count": len(verified),
        "representative_target": representative.get("target") or representative.get("url"),
        "representative_verification": verification,
    }


def status_is_success(probe: ProbeResult) -> bool:
    return probe.status_code is not None and 200 <= probe.status_code < 300


def final_url_in_scope(probe: ProbeResult, config: ScopeConfig) -> bool:
    return config.scope.decide(probe.final_url).allowed


def parse_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def extract_schema_urls(text: str) -> list[str]:
    values = re.findall(r"['\"]([^'\"]*(?:openapi|swagger|api-docs)[^'\"]*)['\"]", text, re.I)
    output: list[str] = []
    for value in values:
        if value.startswith(("http://", "https://", "/", ".")):
            output.append(value)
    return sorted(set(output))


def sensitive_paths(paths: list[str], keywords: tuple[str, ...]) -> list[str]:
    output: list[str] = []
    for path in paths:
        lowered = path.lower()
        if any(keyword in lowered for keyword in keywords):
            output.append(path)
    return output


def has_resource_keyword(path_parts: list[str], query_names: set[str]) -> bool:
    normalized_parts = {part.strip("{}").lower() for part in path_parts}
    if normalized_parts & RESOURCE_KEYWORDS:
        return True
    return any(any(resource in name for resource in RESOURCE_KEYWORDS) for name in query_names)


def has_object_identifier(
    path_parts: list[str],
    query_pairs: list[tuple[str, str]],
    endpoint: dict[str, Any] | None,
) -> bool:
    for part in path_parts:
        stripped = part.strip("{}").lower()
        if part.isdigit() or is_uuid_like(part):
            return True
        if stripped in {"id", "uuid"} or stripped.endswith("_id") or stripped.endswith("-id"):
            return True
    for name, value in query_pairs:
        normalized = name.lower()
        if normalized in NOT_OBJECT_ID_PARAMS:
            continue
        if normalized in {"id", "uuid"} or normalized.endswith("_id") or normalized.endswith("-id"):
            return bool(value)
    if endpoint:
        params = {str(item).lower() for item in endpoint.get("params") or []}
        return any(
            item not in NOT_OBJECT_ID_PARAMS
            and (item in {"id", "uuid"} or item.endswith("_id") or item.endswith("-id"))
            for item in params
        )
    return False


def is_uuid_like(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


def append_unique(value: object, item: str) -> list[str]:
    if isinstance(value, list):
        output = [str(existing) for existing in value]
    elif value:
        output = [str(value)]
    else:
        output = []
    if item not in output:
        output.append(item)
    return output


def absolute_schema_url(base_url: str, schema_url: str) -> str:
    return urljoin(base_url, schema_url)
