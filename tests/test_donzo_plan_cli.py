from __future__ import annotations

import json
from pathlib import Path

from donzo.cli import main
from donzo.config import load_scope_config
from donzo.recon.plan import build_recon_plan


def test_fast_plan_disables_nuclei_when_policy_false() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plan = build_recon_plan(config, profile="fast")
    modules = {
        module["name"]: module for phase in plan.to_dict()["phases"] for module in phase["modules"]
    }
    assert modules["nuclei_safe"]["enabled"] is False
    assert modules["nuclei_safe"]["reason"] == "disabled_by_scan_policy:nuclei_scan"
    assert modules["httpx"]["enabled"] is True
    assert modules["subfinder"]["enabled"] is True


def test_normal_plan_includes_llm_tribunal() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plan = build_recon_plan(config, profile="normal")
    modules = {
        module["name"]: module for phase in plan.to_dict()["phases"] for module in phase["modules"]
    }
    assert modules["llm_candidate_generator"]["enabled"] is True
    assert modules["llm_candidate_generator"]["reason"] == "enabled_by_mandatory_llm:codex_cli"
    assert modules["llm_tribunal"]["enabled"] is True
    assert modules["llm_tribunal"]["reason"] == "enabled_by_mandatory_llm:codex_cli"
    assert modules["llm_report_writer"]["enabled"] is True
    assert modules["llm_report_writer"]["reason"] == "enabled_by_mandatory_llm:codex_cli"


def test_cli_scope_check_outputs_json(capsys) -> None:
    code = main(
        [
            "scope",
            "check",
            "-c",
            "scope.example.yaml",
            "--target",
            "https://api.example.com/v1/users",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["allowed"] is True


def test_cli_scope_check_returns_nonzero_for_out_of_scope(capsys) -> None:
    code = main(
        [
            "scope",
            "check",
            "-c",
            "scope.example.yaml",
            "--target",
            "https://payments.example.com/status",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 2
    assert result["allowed"] is False
