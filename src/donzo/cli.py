from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from donzo.config import load_scope_config
from donzo.llm_triage.stages import load_json_records, run_candidate_generation, run_report_draft
from donzo.llm_triage.tribunal import load_finding, run_tribunal, should_triage_with_llm
from donzo.policy import build_policy_report
from donzo.recon.plan import build_recon_plan
from donzo.scope import ScopeDecision


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _decision_to_dict(decision: ScopeDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "target": decision.target,
        "target_type": decision.target_type,
        "reasons": decision.reasons,
        "matched_in_scope": decision.matched_in_scope,
        "matched_out_of_scope": decision.matched_out_of_scope,
    }


def cmd_scope_validate(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    _print_json(report.to_dict())
    return 0 if report.valid else 2


def cmd_scope_check(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    decision = config.scope.decide(args.target)
    result = _decision_to_dict(decision)
    if args.test_type:
        test_allowed = config.policy.is_test_type_allowed(args.test_type)
        result["test_type"] = args.test_type
        result["test_type_allowed"] = test_allowed
        if not test_allowed:
            result["allowed"] = False
            result["reasons"].append(f"blocked_test_type:{args.test_type}")
    _print_json(result)
    return 0 if result["allowed"] else 2


def cmd_plan(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict(), "plan": []})
        return 2
    plan = build_recon_plan(config, profile=args.profile)
    _print_json({"valid": True, "policy": report.to_dict(), "plan": plan.to_dict()})
    return 0


def cmd_tribunal_run(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2

    finding = load_finding(args.input)
    if not args.force and not should_triage_with_llm(finding):
        _print_json(
            {
                "triaged": False,
                "reason": "finding_type_or_severity_not_selected_for_tribunal",
                "policy": report.to_dict(),
            }
        )
        return 0

    target = str(finding.get("target") or finding.get("url") or finding.get("matched-at") or "")
    target_allowed = config.scope.decide(target).allowed if target else False
    result = run_tribunal(
        finding,
        config=config,
        llm_config=config.llm,
        driver_name=args.driver,
        allow_external_llm=args.allow_external_llm,
        target_allowed=target_allowed,
    )
    _print_json({"triaged": True, "policy": report.to_dict(), "result": result.to_dict()})
    return 0 if result.llm_status == "succeeded" else 3


def cmd_candidates_generate(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    records = load_json_records(args.input)
    result = run_candidate_generation(
        records,
        config=config,
        llm_config=config.llm,
        driver_name=args.driver,
        allow_external_llm=args.allow_external_llm,
    )
    _print_json(
        {
            "generated": result.llm_status == "succeeded",
            "policy": report.to_dict(),
            "result": result.to_dict(),
        }
    )
    return 0 if result.llm_status in {"succeeded", "not_submitted"} else 3


def cmd_report_draft(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    records = load_json_records(args.input)
    result = run_report_draft(
        records,
        config=config,
        llm_config=config.llm,
        driver_name=args.driver,
        allow_external_llm=args.allow_external_llm,
    )
    if result.llm_status == "succeeded" and result.output and args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(str(result.output["markdown"]), encoding="utf-8")
    _print_json(
        {
            "drafted": result.llm_status == "succeeded",
            "policy": report.to_dict(),
            "result": result.to_dict(),
        }
    )
    return 0 if result.llm_status in {"succeeded", "not_submitted"} else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="donzo")
    parser.add_argument("--version", action="version", version="donzo 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scope_parser = subparsers.add_parser("scope", help="Scope validation commands")
    scope_subparsers = scope_parser.add_subparsers(dest="scope_command", required=True)

    validate_parser = scope_subparsers.add_parser("validate", help="Validate a scope file")
    validate_parser.add_argument("-c", "--config", type=Path, required=True)
    validate_parser.add_argument("--allow-risky", action="store_true")
    validate_parser.set_defaults(func=cmd_scope_validate)

    check_parser = scope_subparsers.add_parser("check", help="Check whether a target is in scope")
    check_parser.add_argument("-c", "--config", type=Path, required=True)
    check_parser.add_argument("--target", required=True)
    check_parser.add_argument("--test-type")
    check_parser.set_defaults(func=cmd_scope_check)

    plan_parser = subparsers.add_parser("plan", help="Build a safe recon plan")
    plan_parser.add_argument("-c", "--config", type=Path, required=True)
    plan_parser.add_argument("-p", "--profile", choices=["fast", "normal", "deep"])
    plan_parser.add_argument("--allow-risky", action="store_true")
    plan_parser.set_defaults(func=cmd_plan)

    candidates_parser = subparsers.add_parser("candidates", help="LLM candidate commands")
    candidates_subparsers = candidates_parser.add_subparsers(
        dest="candidates_command",
        required=True,
    )
    candidates_generate_parser = candidates_subparsers.add_parser(
        "generate",
        help="Generate manual-review vulnerability candidates from JSON or JSONL records",
    )
    candidates_generate_parser.add_argument("-c", "--config", type=Path, required=True)
    candidates_generate_parser.add_argument("-i", "--input", type=Path, required=True)
    candidates_generate_parser.add_argument(
        "--driver",
        choices=["auto", "openai", "anthropic", "codex_cli"],
        default="auto",
    )
    candidates_generate_parser.add_argument("--allow-risky", action="store_true")
    candidates_generate_parser.add_argument("--allow-external-llm", action="store_true")
    candidates_generate_parser.set_defaults(func=cmd_candidates_generate)

    tribunal_parser = subparsers.add_parser("tribunal", help="LLM tribunal commands")
    tribunal_subparsers = tribunal_parser.add_subparsers(
        dest="tribunal_command",
        required=True,
    )

    tribunal_run_parser = tribunal_subparsers.add_parser(
        "run",
        help="Run tribunal triage for one finding JSON object",
    )
    tribunal_run_parser.add_argument("-c", "--config", type=Path, required=True)
    tribunal_run_parser.add_argument("-i", "--input", type=Path, required=True)
    tribunal_run_parser.add_argument(
        "--driver",
        choices=["auto", "openai", "anthropic", "codex_cli"],
        default="auto",
    )
    tribunal_run_parser.add_argument("--allow-risky", action="store_true")
    tribunal_run_parser.add_argument("--allow-external-llm", action="store_true")
    tribunal_run_parser.add_argument("--force", action="store_true")
    tribunal_run_parser.set_defaults(func=cmd_tribunal_run)

    report_parser = subparsers.add_parser("report", help="LLM report drafting commands")
    report_subparsers = report_parser.add_subparsers(
        dest="report_command",
        required=True,
    )
    report_draft_parser = report_subparsers.add_parser(
        "draft",
        help="Draft a human-review Markdown report from JSON or JSONL findings",
    )
    report_draft_parser.add_argument("-c", "--config", type=Path, required=True)
    report_draft_parser.add_argument("-i", "--input", type=Path, required=True)
    report_draft_parser.add_argument("-o", "--output", type=Path)
    report_draft_parser.add_argument(
        "--driver",
        choices=["auto", "openai", "anthropic", "codex_cli"],
        default="auto",
    )
    report_draft_parser.add_argument("--allow-risky", action="store_true")
    report_draft_parser.add_argument("--allow-external-llm", action="store_true")
    report_draft_parser.set_defaults(func=cmd_report_draft)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
