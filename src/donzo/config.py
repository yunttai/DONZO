from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from donzo.policy import ScanPolicy
from donzo.scope import Scope


@dataclass(frozen=True)
class RateLimit:
    max_requests_per_second: float = 3
    max_concurrency: int = 5
    timeout_seconds: float = 10

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> RateLimit:
        data = data or {}
        return cls(
            max_requests_per_second=float(data.get("max_requests_per_second", 3)),
            max_concurrency=int(data.get("max_concurrency", 5)),
            timeout_seconds=float(data.get("timeout_seconds", 10)),
        )


@dataclass(frozen=True)
class AuthenticatedCrawlConfig:
    enabled: bool = False
    header_env: str = ""
    cookie_env: str = ""
    allowed_domains: tuple[str, ...] = ()
    pass_to_tools: bool = True
    pass_to_probes: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> AuthenticatedCrawlConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            header_env=str(data.get("header_env", "")),
            cookie_env=str(data.get("cookie_env", "")),
            allowed_domains=tuple(str(item).lower() for item in data.get("allowed_domains") or ()),
            pass_to_tools=bool(data.get("pass_to_tools", True)),
            pass_to_probes=bool(data.get("pass_to_probes", True)),
        )


@dataclass(frozen=True)
class ProbeConfig:
    max_requests_per_candidate: int = 2
    max_network_probes: int = 24
    origin_timeout_threshold: int = 2
    allowed_methods: tuple[str, ...] = ("HEAD", "GET", "OPTIONS")
    allow_post: bool = False
    follow_redirects: bool = True
    max_redirects: int = 2
    timeout_seconds: float = 10.0
    max_body_bytes: int = 200_000
    redact_sensitive_data: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> ProbeConfig:
        data = data or {}
        allowed_methods = data.get("allowed_methods")
        return cls(
            max_requests_per_candidate=max(1, int(data.get("max_requests_per_candidate", 2))),
            max_network_probes=max(0, int(data.get("max_network_probes", 24))),
            origin_timeout_threshold=max(0, int(data.get("origin_timeout_threshold", 2))),
            allowed_methods=tuple(
                str(item).upper() for item in (allowed_methods or cls.allowed_methods)
            ),
            allow_post=bool(data.get("allow_post", False)),
            follow_redirects=bool(data.get("follow_redirects", True)),
            max_redirects=max(0, int(data.get("max_redirects", 2))),
            timeout_seconds=float(data.get("timeout_seconds", 10.0)),
            max_body_bytes=max(1024, int(data.get("max_body_bytes", 200_000))),
            redact_sensitive_data=bool(data.get("redact_sensitive_data", True)),
        )

    def method_allowed(self, method: str) -> bool:
        normalized = method.upper()
        if normalized == "POST" and not self.allow_post:
            return False
        return normalized in set(self.allowed_methods)


@dataclass(frozen=True)
class Soft404Config:
    enabled: bool = True
    baseline_per_host: bool = True
    random_probe_count: int = 1
    similarity_threshold: float = 0.92
    content_length_tolerance_ratio: float = 0.10

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> Soft404Config:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            baseline_per_host=bool(data.get("baseline_per_host", True)),
            random_probe_count=max(1, int(data.get("random_probe_count", 1))),
            similarity_threshold=float(data.get("similarity_threshold", 0.92)),
            content_length_tolerance_ratio=float(data.get("content_length_tolerance_ratio", 0.10)),
        )


@dataclass(frozen=True)
class APIDocsVerificationConfig:
    enabled: bool = True
    verify_schema_url: bool = True
    max_schema_fetches: int = 2
    require_fingerprint: bool = True
    sensitive_path_keywords: tuple[str, ...] = (
        "user",
        "account",
        "order",
        "invoice",
        "document",
        "file",
        "admin",
        "payment",
    )

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> APIDocsVerificationConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            verify_schema_url=bool(data.get("verify_schema_url", True)),
            max_schema_fetches=max(0, int(data.get("max_schema_fetches", 2))),
            require_fingerprint=bool(data.get("require_fingerprint", True)),
            sensitive_path_keywords=tuple(
                str(item).lower()
                for item in data.get("sensitive_path_keywords") or cls.sensitive_path_keywords
            ),
        )


@dataclass(frozen=True)
class SourceMapVerificationConfig:
    enabled: bool = True
    require_json_parse: bool = True
    store_full_map: bool = False
    store_sources_content: bool = False
    max_map_bytes: int = 1_000_000

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> SourceMapVerificationConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            require_json_parse=bool(data.get("require_json_parse", True)),
            store_full_map=bool(data.get("store_full_map", False)),
            store_sources_content=bool(data.get("store_sources_content", False)),
            max_map_bytes=max(1024, int(data.get("max_map_bytes", 1_000_000))),
        )


@dataclass(frozen=True)
class GraphQLVerificationConfig:
    enabled: bool = True
    safe_query_test: bool = False
    introspection_test: bool = False
    require_graphql_fingerprint: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> GraphQLVerificationConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            safe_query_test=bool(data.get("safe_query_test", False)),
            introspection_test=bool(data.get("introspection_test", False)),
            require_graphql_fingerprint=bool(data.get("require_graphql_fingerprint", True)),
        )


@dataclass(frozen=True)
class BOLAFilterConfig:
    enabled: bool = True
    filter_auth_endpoints: bool = True
    require_resource_keyword: bool = True
    require_object_id: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> BOLAFilterConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            filter_auth_endpoints=bool(data.get("filter_auth_endpoints", True)),
            require_resource_keyword=bool(data.get("require_resource_keyword", True)),
            require_object_id=bool(data.get("require_object_id", True)),
        )


@dataclass(frozen=True)
class RedirectFilterConfig:
    enabled: bool = True
    filter_login_redirects: bool = True
    filter_home_redirects: bool = True
    keep_for_open_redirect_candidates: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> RedirectFilterConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            filter_login_redirects=bool(data.get("filter_login_redirects", True)),
            filter_home_redirects=bool(data.get("filter_home_redirects", True)),
            keep_for_open_redirect_candidates=bool(
                data.get("keep_for_open_redirect_candidates", True)
            ),
        )


@dataclass(frozen=True)
class ClusterVerificationConfig:
    enabled: bool = True
    triage_unit: str = "cluster"
    min_verified_candidates_for_cluster: int = 1
    exclude_common_error_clusters: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> ClusterVerificationConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            triage_unit=str(data.get("triage_unit", "cluster")),
            min_verified_candidates_for_cluster=max(
                1,
                int(data.get("min_verified_candidates_for_cluster", 1)),
            ),
            exclude_common_error_clusters=bool(data.get("exclude_common_error_clusters", True)),
        )


@dataclass(frozen=True)
class VerificationConfig:
    enabled: bool = True
    fail_closed: bool = True
    network_probe: bool = True
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    soft404: Soft404Config = field(default_factory=Soft404Config)
    api_docs: APIDocsVerificationConfig = field(default_factory=APIDocsVerificationConfig)
    sourcemap: SourceMapVerificationConfig = field(default_factory=SourceMapVerificationConfig)
    graphql: GraphQLVerificationConfig = field(default_factory=GraphQLVerificationConfig)
    bola_filter: BOLAFilterConfig = field(default_factory=BOLAFilterConfig)
    redirect_filter: RedirectFilterConfig = field(default_factory=RedirectFilterConfig)
    cluster: ClusterVerificationConfig = field(default_factory=ClusterVerificationConfig)

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> VerificationConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            fail_closed=bool(data.get("fail_closed", True)),
            network_probe=bool(data.get("network_probe", True)),
            probe=ProbeConfig.from_mapping(data.get("probe")),
            soft404=Soft404Config.from_mapping(data.get("soft404")),
            api_docs=APIDocsVerificationConfig.from_mapping(data.get("api_docs")),
            sourcemap=SourceMapVerificationConfig.from_mapping(data.get("sourcemap")),
            graphql=GraphQLVerificationConfig.from_mapping(data.get("graphql")),
            bola_filter=BOLAFilterConfig.from_mapping(data.get("bola_filter")),
            redirect_filter=RedirectFilterConfig.from_mapping(data.get("redirect_filter")),
            cluster=ClusterVerificationConfig.from_mapping(data.get("cluster")),
        )


@dataclass(frozen=True)
class LLMDriverConfig:
    enabled: bool = False
    command: str = ""
    model: str = ""
    model_reasoning_effort: str = ""
    temperature: float = 0.0
    json_schema_required: bool = True
    timeout_seconds: float = 180.0
    max_attempts: int = 2
    output_dir: str = "artifacts/llm"
    sandbox: str = "read-only"
    ignore_user_config: bool = True
    ignore_rules: bool = True
    strict_config: bool = True
    json_events: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> LLMDriverConfig:
        data = data or {}
        return cls(
            enabled=bool(data.get("enabled", False)),
            command=str(data.get("command", "")),
            model=str(data.get("model", "")),
            model_reasoning_effort=str(data.get("model_reasoning_effort", "")),
            temperature=float(data.get("temperature", 0.0)),
            json_schema_required=bool(data.get("json_schema_required", True)),
            timeout_seconds=float(data.get("timeout_seconds", 180.0)),
            max_attempts=max(1, int(data.get("max_attempts", 2))),
            output_dir=str(data.get("output_dir", "artifacts/llm")),
            sandbox=str(data.get("sandbox", "read-only")),
            ignore_user_config=bool(data.get("ignore_user_config", True)),
            ignore_rules=bool(data.get("ignore_rules", True)),
            strict_config=bool(data.get("strict_config", True)),
            json_events=bool(data.get("json_events", True)),
        )


@dataclass(frozen=True)
class LLMConfig:
    required: bool = True
    fail_closed: bool = True
    primary_provider: str = "codex_cli"
    secondary_provider: str = "openai"
    drivers: dict[str, LLMDriverConfig] | None = None
    failure_policy: dict[str, str | bool] | None = None
    privacy: dict[str, str | int | bool] | None = None
    stages: dict[str, bool] | None = None
    safety: dict[str, bool] | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> LLMConfig:
        data = data or {}
        drivers = {
            str(name): LLMDriverConfig.from_mapping(config)
            for name, config in (data.get("drivers") or {}).items()
        }
        return cls(
            required=bool(data.get("required", True)),
            fail_closed=bool(data.get("fail_closed", True)),
            primary_provider=str(data.get("primary_provider", "codex_cli")),
            secondary_provider=str(data.get("secondary_provider", "openai")),
            drivers=drivers,
            failure_policy={
                str(key): value for key, value in (data.get("failure_policy") or {}).items()
            },
            privacy={str(key): value for key, value in (data.get("privacy") or {}).items()},
            stages={str(key): bool(value) for key, value in (data.get("stages") or {}).items()},
            safety={str(key): bool(value) for key, value in (data.get("safety") or {}).items()},
        )

    def safety_flag(self, name: str) -> bool:
        if self.safety is None:
            return True
        return self.safety.get(name, True)

    def failure_policy_value(self, name: str, default: str | bool) -> str | bool:
        if self.failure_policy is None:
            return default
        return self.failure_policy.get(name, default)

    def privacy_value(self, name: str, default: str | int | bool) -> str | int | bool:
        if self.privacy is None:
            return default
        return self.privacy.get(name, default)


@dataclass(frozen=True)
class ScopeConfig:
    program_name: str
    profile: str
    mode: str
    scope: Scope
    policy: ScanPolicy
    rate_limit: RateLimit
    authenticated_crawl: AuthenticatedCrawlConfig
    verification: VerificationConfig
    llm: LLMConfig
    source_path: Path

    @classmethod
    def from_mapping(cls, data: dict[str, Any], source_path: Path) -> ScopeConfig:
        return cls(
            program_name=str(data.get("program_name", "")),
            profile=str(data.get("profile", "fast")),
            mode=str(data.get("mode", "")),
            scope=Scope.from_mapping(data),
            policy=ScanPolicy.from_mapping(data.get("scan_policy"), data.get("out_of_scope")),
            rate_limit=RateLimit.from_mapping(data.get("rate_limit")),
            authenticated_crawl=AuthenticatedCrawlConfig.from_mapping(
                data.get("authenticated_crawl")
            ),
            verification=VerificationConfig.from_mapping(data.get("verification")),
            llm=LLMConfig.from_mapping(data.get("llm")),
            source_path=source_path,
        )


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return data


def load_scope_config(path: Path) -> ScopeConfig:
    return ScopeConfig.from_mapping(load_yaml_mapping(path), path)
