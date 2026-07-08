from __future__ import annotations

from typing import Any

EXECUTION_MODES = {
    "plan_only",
    "manual_assist",
    "assisted",
    "controlled",
    "redteam",
    "lab",
    "live",
}

OAST_REQUIRED_CLASSES = {"SSRF", "XXE", "COMMAND_INJECTION"}
EXPLICIT_OPT_IN_CLASSES = {
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "FILE_UPLOAD",
    "DESTRUCTIVE_MUTATION",
}
BLOCKED_ACTIONS = {
    "mass_id_enumeration",
    "destructive_mutation",
    "denial_of_service",
    "credential_attack",
    "malware_upload",
    "reverse_shell",
    "sensitive_file_read",
    "third_party_data_access",
    "cloud_metadata_access_without_explicit_authorization",
}


def evaluate_fuzz_safety(
    plan: dict[str, Any],
    *,
    mode: str = "plan_only",
    oast_enabled: bool = False,
) -> dict[str, Any]:
    normalized_mode = mode.strip().lower()
    vulnerability_class = str(plan.get("vulnerability_class") or "").upper()
    safety = plan.get("safety") if isinstance(plan.get("safety"), dict) else {}
    reasons: list[str] = []

    if normalized_mode not in EXECUTION_MODES:
        reasons.append(f"unknown_mode:{mode}")
    if safety.get("destructive") is True:
        reasons.append("destructive_probe_blocked")

    requested = {
        str(item).strip().lower()
        for item in safety.get("requested_actions") or []
        if str(item).strip()
    }
    blocked_requested = sorted(requested & BLOCKED_ACTIONS)
    reasons.extend(f"blocked_action:{item}" for item in blocked_requested)

    if vulnerability_class in OAST_REQUIRED_CLASSES and not oast_enabled:
        reasons.append("requires_oast:disabled")

    if (
        vulnerability_class in EXPLICIT_OPT_IN_CLASSES
        and not safety.get("explicit_opt_in")
        and normalized_mode not in {"plan_only", "manual_assist"}
    ):
        reasons.append(f"explicit_opt_in_required:{vulnerability_class}")

    if normalized_mode in {"live", "redteam"}:
        if not safety.get("explicit_scope"):
            reasons.append(f"{normalized_mode}_requires:explicit_scope")
        if not safety.get("scope_guarded"):
            reasons.append(f"{normalized_mode}_requires:scope_guard")
        if not safety.get("rate_limited"):
            reasons.append(f"{normalized_mode}_requires:rate_limit")

    max_requests = safety.get("max_requests")
    try:
        if max_requests is not None and int(max_requests) > 50:
            reasons.append("max_requests_above_safe_default")
    except (TypeError, ValueError):
        reasons.append("invalid_max_requests")

    allowed = not reasons
    return {
        "allowed": allowed,
        "status": "allowed" if allowed else "blocked_by_safety_policy",
        "mode": normalized_mode,
        "vulnerability_class": vulnerability_class,
        "reasons": reasons,
    }
