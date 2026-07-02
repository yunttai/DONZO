from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from donzo.candidates.basic import build_basic_candidates
from donzo.config import load_scope_config
from donzo.dedupe import dedupe_records
from donzo.evidence import write_evidence_notes
from donzo.llm_triage.drivers.base import LLMCallError
from donzo.llm_triage.drivers.codex_cli import CodexCliDriver
from donzo.llm_triage.stages import (
    load_json_records,
    run_candidate_generation,
    run_report_draft,
)
from donzo.llm_triage.tribunal import load_finding, run_tribunal, should_triage_with_llm
from donzo.models import now_utc
from donzo.normalize.artifacts import (
    normalize_asset_lines,
    normalize_endpoint_records,
    normalize_finding_records,
    normalize_httpx_records,
)
from donzo.parameters import build_parameters_from_endpoints
from donzo.pipeline import run_fast_pipeline
from donzo.policy import build_policy_report
from donzo.ranking import rank_records
from donzo.recon.plan import build_recon_plan
from donzo.reporting.markdown import render_markdown_report
from donzo.scope import ScopeDecision
from donzo.storage.jsonl import load_text_lines, write_json, write_jsonl
from donzo.tools import check_tools, install_plan, run_install_plan


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


def cmd_tools_check(args: argparse.Namespace) -> int:
    names = args.tools if args.tools else None
    status = check_tools(names)
    missing_required = [
        item for item in status if item["required_for_fast"] and not item["available"]
    ]
    _print_json(
        {
            "ok": not missing_required,
            "missing_required_fast": missing_required,
            "tools": status,
        }
    )
    return 0 if not missing_required else 2


def cmd_tools_install_plan(args: argparse.Namespace) -> int:
    plans = install_plan(args.tools if args.tools else None)
    _print_json({"execute": False, "plans": plans})
    return 0


def cmd_tools_install(args: argparse.Namespace) -> int:
    plans = install_plan(args.tools if args.tools else None)
    if not args.execute:
        _print_json(
            {
                "execute": False,
                "reason": "pass --execute to run go install commands",
                "plans": plans,
            }
        )
        return 0
    results = run_install_plan(args.tools if args.tools else None)
    _print_json({"execute": True, "results": results})
    return 0 if all(item.get("returncode") == 0 for item in results) else 3


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    policy = build_policy_report(config, allow_risky=args.allow_risky)
    tool_status = check_tools(["subfinder", "dnsx", "httpx", "katana"])
    missing_required = [
        item for item in tool_status if item["required_for_fast"] and not item["available"]
    ]
    codex_status = codex_preflight_status(config)
    ok = policy.valid and not missing_required and bool(codex_status["ok"])
    _print_json(
        {
            "ok": ok,
            "policy": policy.to_dict(),
            "tools": {
                "ok": not missing_required,
                "missing_required_fast": missing_required,
                "items": tool_status,
            },
            "codex_cli": codex_status,
        }
    )
    return 0 if ok else 2


def codex_preflight_status(config: Any) -> dict[str, Any]:
    driver_config = (config.llm.drivers or {}).get("codex_cli")
    if driver_config is None or not driver_config.enabled:
        return {
            "ok": False,
            "enabled": False,
            "error": "llm.drivers.codex_cli.enabled must be true",
        }
    try:
        preflight = CodexCliDriver(config.llm, allow_external_llm=False).preflight()
    except LLMCallError as exc:
        return {
            "ok": False,
            "enabled": True,
            "command": driver_config.command,
            "error": str(exc),
        }
    return {
        "ok": True,
        "enabled": True,
        "command": preflight.command,
        "version": preflight.version,
        "doctor": preflight.doctor,
    }


def cmd_run(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    if args.profile != "fast":
        _print_json(
            {
                "valid": False,
                "error": "only fast profile is implemented for donzo run",
                "requested_profile": args.profile,
            }
        )
        return 2
    result = run_fast_pipeline(config=config, output_dir=args.output, execute=args.execute)
    _print_json({"valid": True, "policy": report.to_dict(), "result": result})
    return 0 if "error" not in result else 3


def cmd_normalize(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    text_lines = load_text_lines(args.input) if args.kind == "asset" else []
    records = [] if args.kind == "asset" else load_json_records(args.input)
    if args.kind == "asset":
        normalized, removed = normalize_asset_lines(
            text_lines,
            config=config,
            source=args.source,
        )
    elif args.kind == "httpx":
        normalized, removed = normalize_httpx_records(records, config=config)
    elif args.kind == "endpoint":
        normalized, removed = normalize_endpoint_records(records, config=config, source=args.source)
    else:
        normalized, removed = normalize_finding_records(records, config=config)
    if args.output:
        write_jsonl(args.output, normalized)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "kind": args.kind,
            "input_count": len(text_lines) if args.kind == "asset" else len(records),
            "normalized_count": len(normalized),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
            "removed_output": str(args.removed_output) if args.removed_output else None,
        }
    )
    return 0


def cmd_candidates_build(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    records = load_json_records(args.input)
    scoped, removed = normalize_endpoint_records(records, config=config, source=args.source)
    candidates = dedupe_records(build_basic_candidates(scoped))
    if args.output:
        write_jsonl(args.output, candidates)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "input_count": len(records),
            "endpoint_count": len(scoped),
            "candidate_count": len(candidates),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
        }
    )
    return 0


def cmd_rank(args: argparse.Namespace) -> int:
    records = load_json_records(args.input)
    ranked = rank_records(dedupe_records(records))
    if args.output:
        write_jsonl(args.output, ranked)
    _print_json(
        {
            "input_count": len(records),
            "ranked_count": len(ranked),
            "output": str(args.output) if args.output else None,
        }
    )
    return 0


def cmd_report_render(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    records = load_json_records(args.input)
    markdown = render_markdown_report(
        records,
        program=config.program_name,
        profile=config.profile,
        scope_file=str(args.config),
        removed_count=0,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    _print_json({"rendered": True, "input_count": len(records), "output": str(args.output)})
    return 0


def cmd_run_fixture(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    endpoints = load_json_records(args.endpoints)
    normalized_endpoints, removed = normalize_endpoint_records(
        endpoints,
        config=config,
        source="fixture",
    )
    candidates = dedupe_records(build_basic_candidates(normalized_endpoints))
    params = dedupe_records(build_parameters_from_endpoints(normalized_endpoints))
    findings: list[dict[str, Any]] = []
    ranked = rank_records(candidates)
    args.output.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output / "assets.jsonl", [])
    write_jsonl(args.output / "services.jsonl", [])
    write_jsonl(args.output / "endpoints.jsonl", normalized_endpoints)
    write_jsonl(args.output / "params.jsonl", params)
    write_jsonl(args.output / "candidates.jsonl", candidates)
    write_jsonl(args.output / "findings.jsonl", findings)
    write_jsonl(args.output / "ranked.jsonl", ranked)
    write_json(args.output / "removed.json", removed)
    write_json(
        args.output / "recon-result.json",
        {
            "program": config.program_name,
            "scope_file": str(args.config),
            "generated_at": now_utc(),
            "assets": [],
            "services": [],
            "endpoints": normalized_endpoints,
            "params": params,
            "findings": findings,
        },
    )
    evidence_paths = write_evidence_notes(ranked, args.output / "evidence")
    report_markdown = render_markdown_report(
        ranked,
        program=config.program_name,
        profile=config.profile,
        scope_file=str(args.config),
        removed_count=len(removed),
    )
    (args.output / "report.md").write_text(report_markdown, encoding="utf-8")
    _print_json(
        {
            "valid": True,
            "endpoint_count": len(normalized_endpoints),
            "param_count": len(params),
            "candidate_count": len(candidates),
            "finding_count": len(findings),
            "ranked_count": len(ranked),
            "removed_count": len(removed),
            "evidence_notes": len(evidence_paths),
            "output": str(args.output),
        }
    )
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

    tools_parser = subparsers.add_parser("tools", help="External tool checks")
    tools_subparsers = tools_parser.add_subparsers(dest="tools_command", required=True)
    tools_check_parser = tools_subparsers.add_parser("check", help="Check tool availability")
    tools_check_parser.add_argument("tools", nargs="*")
    tools_check_parser.set_defaults(func=cmd_tools_check)

    tools_install_plan_parser = tools_subparsers.add_parser(
        "install-plan",
        help="Print Go install commands for supported recon tools",
    )
    tools_install_plan_parser.add_argument("tools", nargs="*")
    tools_install_plan_parser.set_defaults(func=cmd_tools_install_plan)

    tools_install_parser = tools_subparsers.add_parser(
        "install",
        help="Install supported recon tools with go install",
    )
    tools_install_parser.add_argument("tools", nargs="*")
    tools_install_parser.add_argument("--execute", action="store_true")
    tools_install_parser.set_defaults(func=cmd_tools_install)

    doctor_parser = subparsers.add_parser("doctor", help="Check DONZO local readiness")
    doctor_parser.add_argument("-c", "--config", type=Path, required=True)
    doctor_parser.add_argument("--allow-risky", action="store_true")
    doctor_parser.set_defaults(func=cmd_doctor)

    run_parser = subparsers.add_parser("run", help="Run a DONZO recon pipeline")
    run_parser.add_argument("-c", "--config", type=Path, required=True)
    run_parser.add_argument("-p", "--profile", choices=["fast", "normal", "deep"], default="fast")
    run_parser.add_argument("-o", "--output", type=Path, required=True)
    run_parser.add_argument("--execute", action="store_true")
    run_parser.add_argument("--allow-risky", action="store_true")
    run_parser.set_defaults(func=cmd_run)

    normalize_parser = subparsers.add_parser("normalize", help="Normalize local artifacts")
    normalize_parser.add_argument("-c", "--config", type=Path, required=True)
    normalize_parser.add_argument("-i", "--input", type=Path, required=True)
    normalize_parser.add_argument("-o", "--output", type=Path)
    normalize_parser.add_argument("--removed-output", type=Path)
    normalize_parser.add_argument("--allow-risky", action="store_true")
    normalize_parser.add_argument("--source", default="artifact")
    normalize_parser.add_argument(
        "--kind",
        choices=["asset", "httpx", "endpoint", "finding"],
        required=True,
    )
    normalize_parser.set_defaults(func=cmd_normalize)

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

    candidates_build_parser = candidates_subparsers.add_parser(
        "build",
        help="Build deterministic manual-review candidates from endpoint artifacts",
    )
    candidates_build_parser.add_argument("-c", "--config", type=Path, required=True)
    candidates_build_parser.add_argument("-i", "--input", type=Path, required=True)
    candidates_build_parser.add_argument("-o", "--output", type=Path)
    candidates_build_parser.add_argument("--removed-output", type=Path)
    candidates_build_parser.add_argument("--allow-risky", action="store_true")
    candidates_build_parser.add_argument("--source", default="candidate_input")
    candidates_build_parser.set_defaults(func=cmd_candidates_build)

    rank_parser = subparsers.add_parser("rank", help="Rank candidates or findings")
    rank_parser.add_argument("-i", "--input", type=Path, required=True)
    rank_parser.add_argument("-o", "--output", type=Path)
    rank_parser.set_defaults(func=cmd_rank)

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

    report_render_parser = report_subparsers.add_parser(
        "render",
        help="Render deterministic Markdown report from ranked JSON or JSONL records",
    )
    report_render_parser.add_argument("-c", "--config", type=Path, required=True)
    report_render_parser.add_argument("-i", "--input", type=Path, required=True)
    report_render_parser.add_argument("-o", "--output", type=Path, required=True)
    report_render_parser.add_argument("--allow-risky", action="store_true")
    report_render_parser.set_defaults(func=cmd_report_render)

    run_fixture_parser = subparsers.add_parser(
        "run-fixture",
        help="Run the local fixture MVP pipeline without network recon",
    )
    run_fixture_parser.add_argument("-c", "--config", type=Path, required=True)
    run_fixture_parser.add_argument("--endpoints", type=Path, required=True)
    run_fixture_parser.add_argument("-o", "--output", type=Path, required=True)
    run_fixture_parser.add_argument("--allow-risky", action="store_true")
    run_fixture_parser.set_defaults(func=cmd_run_fixture)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
