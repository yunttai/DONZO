from __future__ import annotations

from pathlib import Path

from donzo.config import load_scope_config
from donzo.policy import build_policy_report


def test_wildcard_scope_allows_subdomain() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    decision = config.scope.decide("https://api.example.com/v1/users")
    assert decision.allowed is True
    assert "*.example.com" in decision.matched_in_scope


def test_out_of_scope_domain_overrides_wildcard() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    decision = config.scope.decide("https://payments.example.com/status")
    assert decision.allowed is False
    assert "payments.example.com" in decision.matched_out_of_scope


def test_out_of_scope_path_blocks_url() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    decision = config.scope.decide("https://app.example.com/payment/card")
    assert decision.allowed is False
    assert "path:/payment" in decision.matched_out_of_scope


def test_forbidden_test_type_is_blocked() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    assert config.policy.is_test_type_allowed("credential_stuffing") is False


def test_scope_policy_report_is_valid() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    report = build_policy_report(config)
    assert report.valid is True
    assert report.errors == []
