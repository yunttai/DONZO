from __future__ import annotations

from dataclasses import dataclass
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
class LLMDriverConfig:
    enabled: bool = False
    command: str = ""
    model: str = ""
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
