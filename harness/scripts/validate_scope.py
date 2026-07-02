from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

FORBIDDEN_ALWAYS_ON = {
    "active_exploit",
    "automatic_submission",
}

RISKY_REQUIRES_EXPLICIT_ALLOW = {
    "oast",
    "dalfox_candidate",
}

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
    "automatic_exploit",
    "automatic_submission",
    "mass_exploitation",
}


def load_scope(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("scope file must contain a YAML object")
    return data


def _list_at(data: dict[str, Any], *keys: str) -> list[Any]:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict):
            return []
        cur = cur.get(key)
    return cur if isinstance(cur, list) else []


def validate_scope_data(data: dict[str, Any], *, allow_risky: bool = False) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if not data.get("program_name"):
        errors.append("program_name is required")
    if data.get("mode") != "authorized-only":
        errors.append("mode must be authorized-only")

    in_scope_count = sum(
        len(_list_at(data, "in_scope", key)) for key in ("domains", "urls", "ip_ranges")
    )
    if in_scope_count == 0:
        errors.append("at least one in-scope domain, URL, or IP range is required")

    policy = data.get("scan_policy")
    if not isinstance(policy, dict):
        errors.append("scan_policy is required")
        policy = {}

    for key in FORBIDDEN_ALWAYS_ON:
        if policy.get(key) is True:
            errors.append(f"scan_policy.{key} must be false")

    for key in RISKY_REQUIRES_EXPLICIT_ALLOW:
        if policy.get(key) is True and not allow_risky:
            errors.append(f"scan_policy.{key} requires --allow-risky")

    test_types = {str(item).lower() for item in _list_at(data, "out_of_scope", "test_types")}
    missing_forbidden = sorted(FORBIDDEN_TEST_TYPES - test_types)
    if missing_forbidden:
        warnings.append("out_of_scope.test_types does not list all forbidden defaults")

    rate_limit = data.get("rate_limit", {})
    if isinstance(rate_limit, dict):
        rps = rate_limit.get("max_requests_per_second")
        concurrency = rate_limit.get("max_concurrency")
        if rps is not None and float(rps) > 10:
            warnings.append("rate_limit.max_requests_per_second is above conservative default")
        if concurrency is not None and int(concurrency) > 20:
            warnings.append("rate_limit.max_concurrency is above conservative default")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "program_name": data.get("program_name"),
        "profile": data.get("profile"),
        "mode": data.get("mode"),
    }


def validate_scope_file(path: Path, *, allow_risky: bool = False) -> dict[str, Any]:
    return validate_scope_data(load_scope(path), allow_risky=allow_risky)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--allow-risky", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable result")
    args = parser.parse_args()

    result = validate_scope_file(args.scope, allow_risky=args.allow_risky)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
