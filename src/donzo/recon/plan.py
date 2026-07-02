from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PROFILE_MODULES: dict[str, list[str]] = {
    "fast": [
        "scope_validator",
        "subfinder",
        "dnsx",
        "httpx",
        "katana",
        "nuclei_safe",
        "normalize",
        "dedupe",
        "rank",
        "report",
    ],
    "normal": [
        "scope_validator",
        "subfinder",
        "amass_passive",
        "dnsx",
        "httpx",
        "naabu",
        "katana",
        "gau",
        "waybackurls",
        "swagger_finder",
        "graphql_finder",
        "parameter_extractor",
        "nuclei_safe",
        "basic_candidate_engine",
        "llm_candidate_generator",
        "llm_tribunal",
        "normalize",
        "dedupe",
        "rank",
        "evidence_builder",
        "llm_report_writer",
        "report",
    ],
    "deep": [
        "scope_validator",
        "subfinder",
        "amass",
        "bbot",
        "uncover",
        "alterx",
        "dnsx",
        "tlsx",
        "httpx",
        "naabu",
        "katana_headless",
        "gau",
        "waybackurls",
        "waymore",
        "paramspider",
        "ffuf_safe",
        "feroxbuster_safe",
        "kiterunner",
        "js_analyzer",
        "sourcemap_detector",
        "gitleaks",
        "trufflehog",
        "swagger_openapi_analyzer",
        "graphql_analyzer",
        "arjun",
        "gf",
        "qsreplace",
        "kxss",
        "nuclei_deep_safe",
        "zap_baseline_optional",
        "dalfox_candidate_optional",
        "interactsh_optional",
        "bola_idor_candidate_engine",
        "ssrf_candidate_engine",
        "redirect_candidate_engine",
        "file_disclosure_candidate_engine",
        "takeover_candidate_engine",
        "secret_correlation_engine",
        "llm_candidate_generator",
        "llm_tribunal",
        "normalize",
        "dedupe",
        "advanced_rank",
        "evidence_builder",
        "manual_verification_queue",
        "llm_report_writer",
        "report",
    ],
}

POLICY_REQUIRED_FLAGS: dict[str, str] = {
    "httpx": "active_recon",
    "katana": "crawling",
    "katana_headless": "crawling",
    "naabu": "port_scan",
    "gau": "archive_collection",
    "waybackurls": "archive_collection",
    "waymore": "archive_collection",
    "ffuf_safe": "content_discovery",
    "feroxbuster_safe": "content_discovery",
    "arjun": "parameter_mining",
    "nuclei_safe": "nuclei_scan",
    "nuclei_deep_safe": "nuclei_scan",
    "zap_baseline_optional": "zap_baseline",
    "dalfox_candidate_optional": "dalfox_candidate",
    "interactsh_optional": "oast",
}

PHASES: list[tuple[str, list[str]]] = [
    ("scope_policy", ["scope_validator"]),
    ("asset_discovery", ["subfinder", "amass_passive", "amass", "bbot", "uncover"]),
    ("asset_expansion", ["alterx", "dnsx", "tlsx"]),
    ("service_enrichment", ["httpx", "naabu"]),
    ("endpoint_expansion", ["katana", "katana_headless", "gau", "waybackurls", "waymore"]),
    (
        "content_api_discovery",
        ["paramspider", "ffuf_safe", "feroxbuster_safe", "kiterunner"],
    ),
    (
        "analysis",
        [
            "js_analyzer",
            "sourcemap_detector",
            "gitleaks",
            "trufflehog",
            "swagger_finder",
            "graphql_finder",
            "swagger_openapi_analyzer",
            "graphql_analyzer",
            "parameter_extractor",
            "arjun",
            "gf",
            "qsreplace",
            "kxss",
        ],
    ),
    (
        "candidate_engine",
        [
            "basic_candidate_engine",
            "bola_idor_candidate_engine",
            "ssrf_candidate_engine",
            "redirect_candidate_engine",
            "file_disclosure_candidate_engine",
            "takeover_candidate_engine",
            "secret_correlation_engine",
        ],
    ),
    (
        "controlled_scanner",
        [
            "nuclei_safe",
            "nuclei_deep_safe",
            "zap_baseline_optional",
            "dalfox_candidate_optional",
            "interactsh_optional",
        ],
    ),
    (
        "llm_adjudication",
        ["llm_candidate_generator", "llm_tribunal", "llm_report_writer"],
    ),
    (
        "postprocess",
        [
            "normalize",
            "dedupe",
            "rank",
            "advanced_rank",
            "evidence_builder",
            "manual_verification_queue",
            "report",
        ],
    ),
]


@dataclass(frozen=True)
class PlanModule:
    name: str
    enabled: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled, "reason": self.reason}


@dataclass(frozen=True)
class PlanPhase:
    name: str
    modules: list[PlanModule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "modules": [module.to_dict() for module in self.modules]}


@dataclass(frozen=True)
class ReconPlan:
    program_name: str
    profile: str
    phases: list[PlanPhase]

    def to_dict(self) -> dict[str, Any]:
        return {
            "program_name": self.program_name,
            "profile": self.profile,
            "phases": [phase.to_dict() for phase in self.phases],
        }


def build_recon_plan(config: Any, *, profile: str | None = None) -> ReconPlan:
    selected_profile = profile or config.profile
    requested_modules = PROFILE_MODULES[selected_profile]
    requested = set(requested_modules)
    phases: list[PlanPhase] = []

    for phase_name, phase_modules in PHASES:
        modules: list[PlanModule] = []
        for module in phase_modules:
            if module not in requested:
                continue
            enabled, reason = module_policy_state(config, module)
            modules.append(PlanModule(name=module, enabled=enabled, reason=reason))
        if modules:
            phases.append(PlanPhase(name=phase_name, modules=modules))

    return ReconPlan(program_name=config.program_name, profile=selected_profile, phases=phases)


def module_policy_state(config: Any, module: str) -> tuple[bool, str]:
    if module in {"llm_candidate_generator", "llm_tribunal", "llm_report_writer"}:
        if config.llm.required:
            return True, f"enabled_by_mandatory_llm:{config.llm.primary_provider}"
        return False, "invalid_llm_config:not_required"
    flag = POLICY_REQUIRED_FLAGS.get(module)
    if not flag:
        return True, "enabled_by_profile"
    if config.policy.is_enabled(flag):
        return True, f"enabled_by_scan_policy:{flag}"
    return False, f"disabled_by_scan_policy:{flag}"
