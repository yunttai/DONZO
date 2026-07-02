from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FORBIDDEN_TEST_TYPES = {
    "dos",
    "ddos",
    "stress_test",
    "bruteforce",
    "brute_force",
    "credential_stuffing",
    "password_spraying",
    "social_engineering",
    "phishing",
    "malware_upload",
    "destructive_test",
    "data_modification",
    "payment_abuse",
    "session_hijacking",
    "account_takeover_automation",
    "automatic_exploit",
    "automatic_submission",
    "mass_exploitation",
    "automatic_secret_validation",
    "automatic_subdomain_takeover_claim",
}

FORBIDDEN_TRUE_FLAGS = {
    "active_exploit",
    "automatic_submission",
}

RISKY_FLAGS = {
    "oast",
    "dalfox_candidate",
}

REQUIRED_LLM_SAFETY_FLAGS = {
    "no_auto_exploit",
    "no_auto_submission",
    "no_secret_validation",
    "no_takeover_claim",
    "require_manual_verification",
}


@dataclass(frozen=True)
class ScanPolicy:
    flags: dict[str, bool]
    out_of_scope_test_types: set[str]

    @classmethod
    def from_mapping(
        cls,
        scan_policy: dict[str, Any] | None,
        out_of_scope: dict[str, Any] | None,
    ) -> ScanPolicy:
        scan_policy = scan_policy or {}
        out_of_scope = out_of_scope or {}
        test_types = out_of_scope.get("test_types") or []
        return cls(
            flags={str(key): bool(value) for key, value in scan_policy.items()},
            out_of_scope_test_types={str(item).lower() for item in test_types},
        )

    def is_enabled(self, flag: str) -> bool:
        return self.flags.get(flag, False)

    def is_test_type_allowed(self, test_type: str) -> bool:
        normalized = test_type.strip().lower()
        return (
            normalized not in FORBIDDEN_TEST_TYPES
            and normalized not in self.out_of_scope_test_types
        )


@dataclass(frozen=True)
class PolicyReport:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def build_policy_report(config: Any, *, allow_risky: bool = False) -> PolicyReport:
    errors: list[str] = []
    warnings: list[str] = []

    if not config.program_name:
        errors.append("program_name is required")
    if config.mode != "authorized-only":
        errors.append("mode must be authorized-only")
    if config.profile not in {"fast", "normal", "deep"}:
        errors.append("profile must be one of: fast, normal, deep")
    if not config.scope.has_in_scope_targets:
        errors.append("at least one in-scope domain, URL, or IP range is required")

    for flag in sorted(FORBIDDEN_TRUE_FLAGS):
        if config.policy.is_enabled(flag):
            errors.append(f"scan_policy.{flag} must be false")

    for flag in sorted(RISKY_FLAGS):
        if config.policy.is_enabled(flag) and not allow_risky:
            errors.append(f"scan_policy.{flag} requires --allow-risky")

    if not config.llm.required:
        errors.append("llm.required must be true")
    if not config.llm.fail_closed:
        errors.append("llm.fail_closed must be true")
    if config.llm.failure_policy_value("fallback_to_rules", False) is not False:
        errors.append("llm.failure_policy.fallback_to_rules must be false")
    if config.llm.required:
        primary_driver = (config.llm.drivers or {}).get(config.llm.primary_provider)
        if primary_driver is None:
            errors.append(f"llm.drivers.{config.llm.primary_provider} is required")
        elif not primary_driver.enabled:
            errors.append(f"llm.drivers.{config.llm.primary_provider}.enabled must be true")
        elif config.llm.primary_provider == "codex_cli" and not primary_driver.command:
            errors.append("llm.drivers.codex_cli.command is required")
        for flag in sorted(REQUIRED_LLM_SAFETY_FLAGS):
            if not config.llm.safety_flag(flag):
                errors.append(f"llm.safety.{flag} must be true")

    missing_forbidden = sorted(FORBIDDEN_TEST_TYPES - config.policy.out_of_scope_test_types)
    if missing_forbidden:
        warnings.append("out_of_scope.test_types does not list all forbidden defaults")

    if config.rate_limit.max_requests_per_second > 10:
        warnings.append("rate_limit.max_requests_per_second is above conservative default")
    if config.rate_limit.max_concurrency > 20:
        warnings.append("rate_limit.max_concurrency is above conservative default")

    return PolicyReport(valid=not errors, errors=errors, warnings=warnings)
