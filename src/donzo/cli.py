from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, TextIO

from donzo.actors import build_actor_model, load_actor_records
from donzo.analyzers.api_model import build_api_endpoint_models
from donzo.analyzers.artifact_index import build_api_artifact_index
from donzo.analyzers.business_logic import (
    build_business_flow_models,
    build_business_mutation_plans,
    build_business_state_invariants,
)
from donzo.analyzers.dependency_graph import (
    build_api_dependency_graph,
    build_api_sequences,
    build_state_transitions,
)
from donzo.analyzers.discovery import endpoints_from_api_collection_document
from donzo.analyzers.feedback_graph import build_feedback_graph
from donzo.analyzers.graphql_model import (
    build_graphql_logical_endpoint_models,
    build_graphql_operation_models,
    build_graphql_parameter_classifications,
)
from donzo.analyzers.handler_hypothesis import build_handler_hypotheses
from donzo.analyzers.invariants import build_security_invariants
from donzo.analyzers.js import (
    api_doc_endpoints,
    extract_endpoints_from_js_text,
    graphql_endpoints,
    js_file_endpoints,
    source_map_endpoints,
)
from donzo.analyzers.openapi import endpoints_from_openapi_document, openapi_document_candidates
from donzo.analyzers.parameter_classifier import build_parameter_classifications
from donzo.analyzers.realtime_model import build_sse_event_models, build_websocket_message_models
from donzo.analyzers.schema_diff import build_schema_diffs
from donzo.analyzers.semantics import build_api_semantic_map
from donzo.analyzers.ui_field_usage import build_ui_field_usage
from donzo.auth import auth_allowed_for_url, auth_summary
from donzo.candidates.basic import build_basic_candidates
from donzo.capture.har_wizard import capture_har_session, write_har_capture_artifacts
from donzo.clustering import cluster_records
from donzo.config import load_scope_config
from donzo.dedupe import dedupe_records
from donzo.evidence import write_evidence_notes
from donzo.llm_triage.agent_interfaces import build_agent_interfaces, build_deterministic_agent_runs
from donzo.llm_triage.agent_outputs import build_agent_output_scaffolds
from donzo.llm_triage.drivers.base import LLMCallError
from donzo.llm_triage.drivers.codex_cli import CodexCliDriver
from donzo.llm_triage.stages import (
    load_json_records,
    run_candidate_generation,
    run_cluster_triage,
    run_report_draft,
)
from donzo.llm_triage.tribunal import load_finding, run_tribunal, should_triage_with_llm
from donzo.models import now_utc
from donzo.normalize.artifacts import (
    normalize_asset_lines,
    normalize_endpoint_lines,
    normalize_endpoint_records,
    normalize_finding_records,
    normalize_httpx_records,
)
from donzo.oracles.evidence_model import build_evidence_index
from donzo.oracles.oracle_evaluator import evaluate_oracle_results
from donzo.oracles.oracle_templates import build_oracle_templates
from donzo.parameters import build_parameters_from_endpoints
from donzo.pipeline import build_llm_triage_input_packs, build_run_diff, run_recon_pipeline
from donzo.planning.test_plans import build_safe_manual_test_plans
from donzo.policy import build_policy_report
from donzo.ranking import rank_records
from donzo.recon.plan import build_recon_plan
from donzo.reporting.markdown import render_markdown_report
from donzo.reporting.regression_case import build_regression_cases
from donzo.reporting.report_draft import build_report_drafts
from donzo.review import (
    build_llm_triage_queue,
    build_review_queue,
    build_run_review_summary,
    render_run_review_markdown,
    render_verification_debug_markdown,
    write_review_artifacts,
)
from donzo.scope import ScopeDecision
from donzo.state import transition_run_state, write_run_state
from donzo.storage.jsonl import load_text_lines, write_json, write_jsonl
from donzo.tools import (
    check_tools,
    install_plan,
    is_required_for_profile,
    required_tool_names,
    run_install_plan,
    tool_matrix,
)
from donzo.traffic.har_ingest import endpoint_records_from_traffic, ingest_har_files
from donzo.verification import build_cluster_evidence_packs, verify_candidates


def load_project_dotenv(paths: list[Path] | None = None) -> list[Path]:
    if paths is None and os.environ.get("PYTEST_CURRENT_TEST"):
        return []
    if os.environ.get("DONZO_DISABLE_DOTENV", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return []

    candidates = paths or [Path.cwd() / ".env"]
    loaded: list[Path] = []
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
                continue
            if key in os.environ:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            os.environ[key] = value
        loaded.append(path)
    return loaded


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _write_run_failure(output_dir: Path, exc: Exception) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    payload = {
        "error": "run_failed",
        "exception_type": type(exc).__name__,
        "message": str(exc),
        "traceback": trace,
    }
    write_json(output_dir / "run-error.json", payload)
    (output_dir / "run-error.txt").write_text(trace, encoding="utf-8")

    state_path = output_dir / "state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}
        if isinstance(state, dict) and state:
            state = transition_run_state(
                state,
                status="failed",
                phase=str(state.get("phase") or "failed"),
                counters=state.get("counters") if isinstance(state.get("counters"), dict) else None,
                artifacts={
                    "run_error": str(output_dir / "run-error.json"),
                    "run_error_text": str(output_dir / "run-error.txt"),
                },
                error=f"{type(exc).__name__}: {exc}",
                completed=True,
            )
            write_run_state(output_dir, state)
    return payload


def _decision_to_dict(decision: ScopeDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "target": decision.target,
        "target_type": decision.target_type,
        "reasons": decision.reasons,
        "matched_in_scope": decision.matched_in_scope,
        "matched_out_of_scope": decision.matched_out_of_scope,
    }


def _default_in_place_progress(stream: TextIO) -> bool:
    mode = os.environ.get("DONZO_PROGRESS_MODE", "").strip().lower()
    if mode in {"in-place", "in_place", "inline", "ansi"}:
        return True
    if mode in {"plain", "append", "snapshot"}:
        return False
    if os.environ.get("CI"):
        return False
    try:
        if stream.isatty():
            return True
    except OSError:
        return False
    if os.name == "nt":
        return any(
            os.environ.get(name) for name in ("WT_SESSION", "TERM_PROGRAM", "VSCODE_PID", "ANSICON")
        )
    return False


def _progress_mode_to_in_place(mode: str) -> bool | None:
    if mode == "in-place":
        return True
    if mode == "plain":
        return False
    return None


class RunProgressRenderer:
    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        bar_width: int = 20,
        in_place: bool | None = None,
    ) -> None:
        self.stream = stream or sys.stderr
        self.bar_width = bar_width
        self.phase_steps: list[dict[str, Any]] = []
        self.steps: list[dict[str, Any]] = []
        self.render_count = 0
        self.last_line_count = 0
        self.in_place = _default_in_place_progress(self.stream) if in_place is None else in_place

    def __call__(self, event: dict[str, Any]) -> None:
        event_name = str(event.get("event") or "")
        if event_name == "plan_ready":
            self.steps = [
                {
                    "name": str(item.get("name") or "step"),
                    "status": "pending" if item.get("allowed", False) else "disabled",
                    "percent": 0,
                }
                for item in event.get("plans") or []
            ]
            self.phase_steps = [
                {
                    "name": str(item.get("name") or "pipeline step"),
                    "status": str(item.get("status") or "pending"),
                    "percent": int(item.get("percent") or 0),
                }
                for item in event.get("pipeline_steps") or []
            ]
        elif event_name == "command_started":
            self.update_step(str(event.get("name") or ""), status="running", percent=10)
            self.update_command_phase(event, error="")
        elif event_name == "command_finished":
            error = event.get("error")
            if event.get("skipped") or error in {
                "command plan is not allowed",
                "optional_tool_missing",
            }:
                self.update_step(str(event.get("name") or ""), status="skipped", percent=0)
            elif error:
                self.update_step(str(event.get("name") or ""), status=f"error:{error}", percent=100)
            else:
                self.update_step(str(event.get("name") or ""), status="done", percent=100)
            self.update_command_phase(event, error=str(error or ""))
        elif event_name == "pipeline_step_started":
            self.update_phase(str(event.get("name") or ""), status="running", percent=10)
        elif event_name == "pipeline_step_finished":
            self.update_phase(str(event.get("name") or ""), status="done", percent=100)
        elif event_name == "pipeline_step_update":
            self.update_phase(
                str(event.get("name") or ""),
                status=str(event.get("status") or "running"),
                percent=int(event.get("percent") or 0),
            )
        elif event_name == "verification_progress":
            processed = int(event.get("processed") or 0)
            total = int(event.get("total") or 0)
            probe_used = int(event.get("probe_used") or 0)
            probe_limit = int(event.get("probe_limit") or 0)
            cached = int(event.get("origin_timeout_cached") or 0)
            status = f"running {processed}/{total} candidates, probes {probe_used}/{probe_limit}"
            if cached:
                status = f"{status}, cached {cached}"
            self.update_phase(
                "verification / filtering",
                status=status,
                percent=int(event.get("percent") or 0),
            )
        elif event_name == "normalization_started":
            if self.phase_steps:
                self.update_phase("parse artifacts", status="running", percent=10)
            else:
                self.ensure_step("normalize/report")
                self.update_step("normalize/report", status="running", percent=10)
        elif event_name == "blocked":
            status = str(event.get("error") or "blocked")
            if self.phase_steps:
                self.update_phase("scope / preflight", status=status, percent=100)
            else:
                self.ensure_step("preflight")
                self.update_step("preflight", status=status, percent=100)
        elif event_name == "completed":
            if self.phase_steps:
                for phase in self.phase_steps:
                    if phase.get("status") not in {"disabled", "skipped"}:
                        phase["status"] = "done"
                        phase["percent"] = 100
            else:
                self.update_step("normalize/report", status="done", percent=100)
        else:
            return
        self.render()

    def ensure_phase(self, name: str) -> None:
        if not any(item["name"] == name for item in self.phase_steps):
            self.phase_steps.append({"name": name, "status": "pending", "percent": 0})

    def update_phase(self, name: str, *, status: str, percent: int) -> None:
        if not name:
            return
        self.ensure_phase(name)
        for item in self.phase_steps:
            if item["name"] == name:
                item["status"] = status
                item["percent"] = max(0, min(100, percent))
                return

    def update_command_phase(self, event: dict[str, Any], *, error: str) -> None:
        if not self.phase_steps:
            return
        index = int(event.get("index") or 0)
        total = int(event.get("total") or 0)
        if error and error not in {"command plan is not allowed", "optional_tool_missing"}:
            self.update_phase("recon commands", status=f"error:{error}", percent=100)
            return
        if index and total:
            percent = max(10, min(100, round(index * 100 / total)))
            status = "done" if index >= total else "running"
        else:
            percent = 10
            status = "running"
        self.update_phase("recon commands", status=status, percent=percent)

    def ensure_step(self, name: str) -> None:
        if not any(item["name"] == name for item in self.steps):
            self.steps.append({"name": name, "status": "pending", "percent": 0})

    def update_step(self, name: str, *, status: str, percent: int) -> None:
        if not name:
            return
        self.ensure_step(name)
        for item in self.steps:
            if item["name"] == name:
                item["status"] = status
                item["percent"] = percent
                return

    def render(self) -> None:
        if not self.steps:
            return
        self.render_count += 1
        lines = self.render_lines()
        line_count = max(len(lines), self.last_line_count)
        if self.in_place and self.last_line_count:
            self.stream.write(f"\x1b[{self.last_line_count}F")
        for index in range(line_count):
            if self.in_place:
                self.stream.write("\x1b[2K")
            if index < len(lines):
                self.stream.write(lines[index])
            self.stream.write("\n")
        if not self.in_place:
            self.stream.write("\n")
        self.last_line_count = len(lines)
        self.stream.flush()

    def render_lines(self) -> list[str]:
        lines = ["DONZO progress"]
        if self.phase_steps:
            lines.append("Pipeline")
            lines.extend(self.render_step_lines(self.phase_steps))
        if self.steps:
            if self.phase_steps:
                lines.append("Tools")
            lines.extend(self.render_step_lines(self.steps))
        return lines

    def render_step_lines(self, steps: list[dict[str, Any]]) -> list[str]:
        lines: list[str] = []
        for index, step in enumerate(steps, start=1):
            percent = int(step.get("percent") or 0)
            status = str(step.get("status") or "pending")
            lines.append(
                f"{index}. {step['name']} [{self.progress_bar(percent)}] ... {percent}% {status}"
            )
        return lines

    def progress_bar(self, percent: int) -> str:
        filled = min(self.bar_width, max(0, round(self.bar_width * percent / 100)))
        return "#" * filled + "-" * (self.bar_width - filled)


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
        item
        for item in status
        if is_required_for_profile(item, args.profile) and not item["available"]
    ]
    _print_json(
        {
            "ok": not missing_required,
            "profile": args.profile,
            "missing_required": missing_required,
            "tools": status,
        }
    )
    return 0 if not missing_required else 2


def cmd_tools_matrix(_args: argparse.Namespace) -> int:
    _print_json(tool_matrix())
    return 0


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
    profile = args.profile or config.profile
    policy = build_policy_report(config, allow_risky=args.allow_risky)
    tool_status = check_tools(required_tool_names(profile))
    missing_required = [
        item
        for item in tool_status
        if is_required_for_profile(item, profile) and not item["available"]
    ]
    codex_status = codex_preflight_status(config)
    ok = policy.valid and not missing_required and bool(codex_status["ok"])
    _print_json(
        {
            "ok": ok,
            "profile": profile,
            "policy": policy.to_dict(),
            "tools": {
                "ok": not missing_required,
                "missing_required": missing_required,
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
    llm_triage_enabled = args.llm_triage or (config.llm.required and not args.no_llm_triage)
    allow_external_llm = False
    if not args.no_external_llm:
        allow_external_llm = args.allow_external_llm or (llm_triage_enabled and config.llm.required)
    try:
        result = run_recon_pipeline(
            config=config,
            output_dir=args.output,
            profile=args.profile,
            execute=args.execute,
            llm_triage=llm_triage_enabled,
            llm_driver=args.llm_driver,
            llm_limit=args.llm_limit,
            allow_external_llm=allow_external_llm,
            compare_to=args.compare_to,
            har_inputs=args.har or [],
            actor_inputs=args.actors or [],
            traffic_actor=args.traffic_actor,
            traffic_role=args.traffic_role,
            traffic_tenant=args.traffic_tenant,
            traffic_state=args.traffic_state,
            traffic_flow=args.traffic_flow,
            traffic_label=args.traffic_label,
            progress_callback=(
                RunProgressRenderer(in_place=_progress_mode_to_in_place(args.progress_mode))
                if args.execute and not args.no_progress
                else None
            ),
        )
    except Exception as exc:
        failure = _write_run_failure(args.output, exc)
        _print_json(
            {
                "valid": True,
                "policy": report.to_dict(),
                "result": {
                    "execute": args.execute,
                    "error": "run_failed",
                    "exception_type": failure["exception_type"],
                    "message": failure["message"],
                    "output": str(args.output),
                    "run_error": str(args.output / "run-error.json"),
                },
            }
        )
        return 3
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


def cmd_analyze_js(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    endpoints, removed = extract_endpoints_from_js_text(
        args.input.read_text(encoding="utf-8"),
        base_url=args.base_url,
        config=config,
        source=args.source,
    )
    endpoints = dedupe_records(endpoints)
    candidates = dedupe_records(build_basic_candidates(endpoints))
    if args.output:
        write_jsonl(args.output, endpoints)
    if args.candidates_output:
        write_jsonl(args.candidates_output, candidates)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "kind": "js",
            "endpoint_count": len(endpoints),
            "candidate_count": len(candidates),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
            "candidates_output": str(args.candidates_output) if args.candidates_output else None,
            "removed_output": str(args.removed_output) if args.removed_output else None,
        }
    )
    return 0


def cmd_analyze_openapi(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    data = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        _print_json({"valid": False, "error": "openapi input must be a JSON object"})
        return 2
    endpoints, removed = endpoints_from_openapi_document(
        data,
        base_url=args.base_url,
        config=config,
        source=args.source,
    )
    endpoints = dedupe_records(endpoints)
    candidates = dedupe_records(build_basic_candidates(endpoints))
    if args.output:
        write_jsonl(args.output, endpoints)
    if args.candidates_output:
        write_jsonl(args.candidates_output, candidates)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "kind": "openapi",
            "endpoint_count": len(endpoints),
            "candidate_count": len(candidates),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
            "candidates_output": str(args.candidates_output) if args.candidates_output else None,
            "removed_output": str(args.removed_output) if args.removed_output else None,
        }
    )
    return 0


def cmd_analyze_collection(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    data = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        _print_json({"valid": False, "error": "collection input must be a JSON object"})
        return 2
    endpoints, removed = endpoints_from_api_collection_document(
        data,
        base_url=args.base_url or "",
        config=config,
        source=args.source,
    )
    endpoints = dedupe_records(endpoints)
    candidates = dedupe_records(build_basic_candidates(endpoints))
    if args.output:
        write_jsonl(args.output, endpoints)
    if args.candidates_output:
        write_jsonl(args.candidates_output, candidates)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "kind": "collection",
            "endpoint_count": len(endpoints),
            "candidate_count": len(candidates),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
            "candidates_output": str(args.candidates_output) if args.candidates_output else None,
            "removed_output": str(args.removed_output) if args.removed_output else None,
        }
    )
    return 0


def cmd_ingest_har(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    traffic, request_schemas, response_schemas, removed = ingest_har_files(
        args.input,
        config=config,
        actor=args.actor,
        role=args.role,
        tenant=args.tenant,
        state=args.state,
        flow=args.flow,
        label=args.label,
        source=args.source,
    )
    endpoint_records = endpoint_records_from_traffic(traffic)
    endpoints, endpoint_removed = normalize_endpoint_records(
        endpoint_records,
        config=config,
        source="har",
    )
    removed.extend(endpoint_removed)
    actor_model = build_actor_model(load_actor_records(args.actors or []), traffic=traffic)
    actors = actor_model.get("actors") or []
    actor_relationships = actor_model.get("relationships") or []
    owned_resources = actor_model.get("owned_resources") or []
    api_semantic_map = build_api_semantic_map(endpoints, config=config)
    api_endpoint_models = build_api_endpoint_models(
        endpoints,
        traffic=traffic,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        api_semantic_map=api_semantic_map,
    )
    graphql_operations = build_graphql_operation_models(traffic)
    graphql_logical_endpoints = build_graphql_logical_endpoint_models(graphql_operations)
    api_endpoint_models.extend(graphql_logical_endpoints)
    parameter_classifications = build_parameter_classifications(
        api_endpoint_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    parameter_classifications.extend(build_graphql_parameter_classifications(graphql_operations))
    schema_diffs = build_schema_diffs(
        api_endpoint_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    ui_field_usage = build_ui_field_usage(
        schema_diffs,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    api_dependency_graph = build_api_dependency_graph(
        api_endpoint_models,
        traffic=traffic,
        parameter_classifications=parameter_classifications,
    )
    api_sequences = build_api_sequences(traffic, api_endpoint_models)
    state_transitions = build_state_transitions(api_sequences)
    handler_hypotheses = build_handler_hypotheses(
        api_endpoint_models,
        parameter_classifications=parameter_classifications,
        dependency_graph=api_dependency_graph,
        schema_diffs=schema_diffs,
    )
    security_invariants = build_security_invariants(
        api_endpoint_models,
        handler_hypotheses=handler_hypotheses,
        parameter_classifications=parameter_classifications,
        schema_diffs=schema_diffs,
        dependency_graph=api_dependency_graph,
        actor_model=actor_model,
    )
    business_flows = build_business_flow_models(
        api_endpoint_models,
        api_sequences=api_sequences,
        state_transitions=state_transitions,
        graphql_operations=graphql_operations,
        actor_model=actor_model,
    )
    business_state_invariants = build_business_state_invariants(business_flows)
    business_mutation_plans = build_business_mutation_plans(business_flows)
    security_invariants = dedupe_json_records_by_field(
        security_invariants + business_state_invariants,
        "invariant_id",
    )
    safe_manual_test_plans = build_safe_manual_test_plans(
        security_invariants,
        api_endpoint_models=api_endpoint_models,
        actor_model=actor_model,
    )
    oracle_templates = build_oracle_templates(safe_manual_test_plans)
    agent_interfaces = build_agent_interfaces()
    agent_runs = build_deterministic_agent_runs(
        api_endpoint_models=api_endpoint_models,
        parameter_classifications=parameter_classifications,
        dependency_graph=api_dependency_graph,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
        oracle_templates=oracle_templates,
    )
    llm_agent_outputs = build_agent_output_scaffolds(
        api_endpoint_models=api_endpoint_models,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
    )
    api_artifact_index = build_api_artifact_index(
        output_dir=args.output.parent if args.output else Path("."),
        api_endpoint_models=api_endpoint_models,
        traffic=traffic,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        parameter_classifications=parameter_classifications,
        schema_diffs=schema_diffs,
        dependency_graph=api_dependency_graph,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        manual_test_plans=safe_manual_test_plans,
        oracle_templates=oracle_templates,
    )
    if args.output:
        write_jsonl(args.output, traffic)
    if args.endpoints_output:
        write_jsonl(args.endpoints_output, endpoints)
    if args.request_schemas_output:
        write_jsonl(args.request_schemas_output, request_schemas)
    if args.response_schemas_output:
        write_jsonl(args.response_schemas_output, response_schemas)
    if args.actors_output:
        write_jsonl(args.actors_output, actors)
    if args.actor_relationships_output:
        write_jsonl(args.actor_relationships_output, actor_relationships)
    if args.owned_resources_output:
        write_jsonl(args.owned_resources_output, owned_resources)
    if args.api_endpoints_output:
        write_jsonl(args.api_endpoints_output, api_endpoint_models)
    if args.graphql_operations_output:
        write_jsonl(args.graphql_operations_output, graphql_operations)
    if args.graphql_logical_endpoints_output:
        write_jsonl(args.graphql_logical_endpoints_output, graphql_logical_endpoints)
    if args.api_artifact_index_output:
        write_json(args.api_artifact_index_output, api_artifact_index)
    if args.ui_field_usage_output:
        write_jsonl(args.ui_field_usage_output, ui_field_usage)
    if args.parameter_classification_output:
        write_jsonl(args.parameter_classification_output, parameter_classifications)
    if args.schema_diff_output:
        write_jsonl(args.schema_diff_output, schema_diffs)
    if args.api_dependency_graph_output:
        write_json(args.api_dependency_graph_output, api_dependency_graph)
    if args.api_sequences_output:
        write_jsonl(args.api_sequences_output, api_sequences)
    if args.state_transitions_output:
        write_jsonl(args.state_transitions_output, state_transitions)
    if args.handler_hypotheses_output:
        write_jsonl(args.handler_hypotheses_output, handler_hypotheses)
    if args.security_invariants_output:
        write_jsonl(args.security_invariants_output, security_invariants)
    if args.business_flows_output:
        write_jsonl(args.business_flows_output, business_flows)
    if args.business_state_invariants_output:
        write_jsonl(args.business_state_invariants_output, business_state_invariants)
    if args.business_mutation_plans_output:
        write_jsonl(args.business_mutation_plans_output, business_mutation_plans)
    if args.manual_test_plans_output:
        write_jsonl(args.manual_test_plans_output, safe_manual_test_plans)
    if args.oracle_templates_output:
        write_jsonl(args.oracle_templates_output, oracle_templates)
    if args.agent_interfaces_output:
        write_json(args.agent_interfaces_output, agent_interfaces)
    if args.agent_runs_output:
        write_jsonl(args.agent_runs_output, agent_runs)
    if args.llm_agent_outputs_output:
        write_jsonl(args.llm_agent_outputs_output, llm_agent_outputs)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "valid": True,
            "policy": report.to_dict(),
            "traffic_count": len(traffic),
            "endpoint_count": len(endpoints),
            "request_schema_count": len(request_schemas),
            "response_schema_count": len(response_schemas),
            "actor_count": len(actors),
            "actor_relationship_count": len(actor_relationships),
            "owned_resource_count": len(owned_resources),
            "api_endpoint_model_count": len(api_endpoint_models),
            "graphql_operation_count": len(graphql_operations),
            "graphql_logical_endpoint_count": len(graphql_logical_endpoints),
            "ui_field_usage_count": len(ui_field_usage),
            "parameter_classification_count": len(parameter_classifications),
            "schema_diff_count": len(schema_diffs),
            "dependency_edge_count": len(api_dependency_graph.get("edges") or []),
            "api_sequence_count": len(api_sequences),
            "state_transition_count": len(state_transitions),
            "handler_hypothesis_count": len(handler_hypotheses),
            "security_invariant_count": len(security_invariants),
            "business_flow_count": len(business_flows),
            "business_state_invariant_count": len(business_state_invariants),
            "business_mutation_plan_count": len(business_mutation_plans),
            "safe_manual_test_plan_count": len(safe_manual_test_plans),
            "oracle_template_count": len(oracle_templates),
            "agent_run_count": len(agent_runs),
            "llm_agent_output_count": len(llm_agent_outputs),
            "removed_count": len(removed),
            "output": str(args.output) if args.output else None,
        }
    )
    return 0


def cmd_auth_check(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    summary = auth_summary(config)
    if args.target:
        target_allowed = auth_allowed_for_url(args.target, config=config)
        summary["target"] = args.target
        summary["target_allowed_for_auth"] = target_allowed
        summary["would_send_header"] = bool(
            target_allowed and int(summary.get("header_count") or 0)
        )
    _print_json({"valid": True, "auth": summary})
    return 0


def cmd_auth_template(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    summary = auth_summary(config)
    auth_header_env = config.authenticated_crawl.header_env or "DONZO_AUTH_HEADER"
    auth_cookie_env = config.authenticated_crawl.cookie_env or "DONZO_AUTH_COOKIE"
    _print_json(
        {
            "valid": True,
            "auth": summary,
            "powershell": {
                "header": f'$env:{auth_header_env}="Authorization: Bearer <token>"',
                "cookie": f'$env:{auth_cookie_env}="session=<cookie>"',
            },
            "notes": [
                "Do not write real cookies or tokens to scope YAML, git, reports, or artifacts.",
                "Use only accounts and data you are authorized to test.",
                "DONZO redacts auth header values from command plans and run artifacts.",
            ],
        }
    )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    output = args.output or (args.current / "run-diff.json")
    result = build_run_diff(args.previous, args.current, output_path=output)
    _print_json(result)
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
    clusters = cluster_records(records)
    markdown = render_markdown_report(
        records,
        program=config.program_name,
        profile=config.profile,
        scope_file=str(args.config),
        removed_count=0,
        clusters=clusters,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    _print_json({"rendered": True, "input_count": len(records), "output": str(args.output)})
    return 0


def cmd_oracle_evaluate(args: argparse.Namespace) -> int:
    test_plans = load_json_records(args.test_plans)
    oracle_templates = load_json_records(args.oracle_templates)
    manual_results = load_json_records(args.manual_results)
    oracle_results = evaluate_oracle_results(
        test_plans,
        oracle_templates,
        manual_results,
    )
    evidence_index = build_evidence_index(oracle_results)
    write_jsonl(args.output, oracle_results)
    if args.evidence_output:
        write_jsonl(args.evidence_output, evidence_index)
    counts: dict[str, int] = {}
    for result in oracle_results:
        status = str((result.get("oracle_verdict") or {}).get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    _print_json(
        {
            "evaluated": True,
            "manual_result_count": len(manual_results),
            "oracle_result_count": len(oracle_results),
            "status_counts": counts,
            "evidence_count": len(evidence_index),
            "output": str(args.output),
            "evidence_output": str(args.evidence_output) if args.evidence_output else None,
        }
    )
    return 0


def cmd_report_from_oracle(args: argparse.Namespace) -> int:
    oracle_results = load_json_records(args.oracle_results)
    test_plans = load_json_records(args.test_plans) if args.test_plans else []
    security_invariants = (
        load_json_records(args.security_invariants) if args.security_invariants else []
    )
    api_endpoint_models = load_json_records(args.api_endpoints) if args.api_endpoints else []
    drafts = build_report_drafts(
        oracle_results,
        test_plans=test_plans,
        security_invariants=security_invariants,
        api_endpoint_models=api_endpoint_models,
    )
    regression_cases = build_regression_cases(
        oracle_results,
        test_plans=test_plans,
        security_invariants=security_invariants,
    )
    write_jsonl(args.drafts_output, drafts)
    if args.regression_output:
        write_jsonl(args.regression_output, regression_cases)
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(render_oracle_report_drafts(drafts), encoding="utf-8")
    _print_json(
        {
            "generated": True,
            "oracle_result_count": len(oracle_results),
            "report_draft_count": len(drafts),
            "regression_case_count": len(regression_cases),
            "drafts_output": str(args.drafts_output),
            "regression_output": str(args.regression_output) if args.regression_output else None,
            "markdown_output": str(args.markdown_output) if args.markdown_output else None,
        }
    )
    return 0


def render_oracle_report_drafts(drafts: list[dict[str, Any]]) -> str:
    lines = ["# Oracle Report Drafts", ""]
    if not drafts:
        lines.extend(["No confirmed oracle results were available for report drafting.", ""])
        return "\n".join(lines)
    for index, draft in enumerate(drafts, start=1):
        lines.extend(
            [
                f"## {index}. {draft.get('title', 'Confirmed Finding')}",
                "",
                f"- Severity Hint: {draft.get('severity_hint', 'medium')}",
                f"- Confidence: {draft.get('confidence', 0)}",
                f"- Affected Endpoint: {draft.get('affected_endpoint', '')}",
                "",
                "### Summary",
                "",
                str(draft.get("summary") or ""),
                "",
                "### Steps To Reproduce",
                "",
            ]
        )
        for step in draft.get("steps_to_reproduce") or []:
            lines.append(f"- {step}")
        lines.extend(["", "### Impact", "", str(draft.get("impact") or ""), ""])
        lines.extend(["### Recommended Fix", "", str(draft.get("recommended_fix") or ""), ""])
        lines.extend(["### Safety Notes", ""])
        for note in draft.get("safety_notes") or []:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines)


def cmd_run_fixture(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    traffic_records: list[dict[str, Any]] = []
    request_schemas: list[dict[str, Any]] = []
    response_schemas: list[dict[str, Any]] = []
    endpoints = load_json_records(args.endpoints)
    normalized_endpoints, removed = normalize_endpoint_records(
        endpoints,
        config=config,
        source="fixture",
    )
    if args.archive_urls:
        archive_endpoints, archive_removed = normalize_endpoint_lines(
            load_text_lines(args.archive_urls),
            config=config,
            source="archive_fixture",
        )
        normalized_endpoints.extend(archive_endpoints)
        removed.extend(archive_removed)
    if args.js_file:
        if not args.js_base_url:
            _print_json({"valid": False, "error": "--js-base-url is required with --js-file"})
            return 2
        js_endpoints, js_removed = extract_endpoints_from_js_text(
            args.js_file.read_text(encoding="utf-8"),
            base_url=args.js_base_url,
            config=config,
            source="js_fixture",
        )
        normalized_endpoints.extend(js_endpoints)
        removed.extend(js_removed)
    if args.openapi:
        if not args.openapi_base_url:
            _print_json({"valid": False, "error": "--openapi-base-url is required with --openapi"})
            return 2
        openapi_data = json.loads(args.openapi.read_text(encoding="utf-8"))
        if not isinstance(openapi_data, dict):
            _print_json({"valid": False, "error": "--openapi must contain a JSON object"})
            return 2
        openapi_endpoints, openapi_removed = endpoints_from_openapi_document(
            openapi_data,
            base_url=args.openapi_base_url,
            config=config,
            source="openapi_fixture",
        )
        normalized_endpoints.extend(openapi_endpoints)
        removed.extend(openapi_removed)
    if args.har:
        traffic_records, request_schemas, response_schemas, traffic_removed = ingest_har_files(
            args.har,
            config=config,
            actor=args.traffic_actor,
            role=args.traffic_role,
            tenant=args.traffic_tenant,
            state=args.traffic_state,
            flow=args.traffic_flow,
            label=args.traffic_label,
            source="har_fixture",
        )
        traffic_endpoints, traffic_endpoint_removed = normalize_endpoint_records(
            endpoint_records_from_traffic(traffic_records),
            config=config,
            source="har_fixture",
        )
        normalized_endpoints.extend(traffic_endpoints)
        removed.extend(traffic_removed)
        removed.extend(traffic_endpoint_removed)
    normalized_endpoints = dedupe_records(normalized_endpoints)
    if args.profile in {"normal", "deep"}:
        api_discovery_endpoints, api_discovery_removed = openapi_document_candidates(
            normalized_endpoints,
            config=config,
        )
        normalized_endpoints = dedupe_records(normalized_endpoints + api_discovery_endpoints)
        removed.extend(api_discovery_removed)
    js_files = js_file_endpoints(normalized_endpoints)
    if args.profile in {"normal", "deep"}:
        source_maps, source_map_removed = source_map_endpoints(js_files, config=config)
        normalized_endpoints = dedupe_records(normalized_endpoints + source_maps)
        removed.extend(source_map_removed)
    else:
        source_maps = []
    js_files = js_file_endpoints(normalized_endpoints)
    api_docs = api_doc_endpoints(normalized_endpoints)
    graphql = graphql_endpoints(normalized_endpoints)
    actor_model = build_actor_model(load_actor_records(args.actors or []), traffic=traffic_records)
    actors = actor_model.get("actors") or []
    actor_relationships = actor_model.get("relationships") or []
    owned_resources = actor_model.get("owned_resources") or []
    api_semantic_map = build_api_semantic_map(normalized_endpoints, config=config)
    api_endpoint_models = build_api_endpoint_models(
        normalized_endpoints,
        traffic=traffic_records,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        api_semantic_map=api_semantic_map,
    )
    graphql_operations = build_graphql_operation_models(traffic_records)
    graphql_logical_endpoints = build_graphql_logical_endpoint_models(graphql_operations)
    api_endpoint_models.extend(graphql_logical_endpoints)
    parameter_classifications = build_parameter_classifications(
        api_endpoint_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    parameter_classifications.extend(build_graphql_parameter_classifications(graphql_operations))
    schema_diffs = build_schema_diffs(
        api_endpoint_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    ui_field_usage = build_ui_field_usage(
        schema_diffs,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    api_dependency_graph = build_api_dependency_graph(
        api_endpoint_models,
        traffic=traffic_records,
        parameter_classifications=parameter_classifications,
    )
    api_sequences = build_api_sequences(traffic_records, api_endpoint_models)
    state_transitions = build_state_transitions(api_sequences)
    handler_hypotheses = build_handler_hypotheses(
        api_endpoint_models,
        parameter_classifications=parameter_classifications,
        dependency_graph=api_dependency_graph,
        schema_diffs=schema_diffs,
    )
    security_invariants = build_security_invariants(
        api_endpoint_models,
        handler_hypotheses=handler_hypotheses,
        parameter_classifications=parameter_classifications,
        schema_diffs=schema_diffs,
        dependency_graph=api_dependency_graph,
        actor_model=actor_model,
    )
    business_flows = build_business_flow_models(
        api_endpoint_models,
        api_sequences=api_sequences,
        state_transitions=state_transitions,
        graphql_operations=graphql_operations,
        actor_model=actor_model,
    )
    business_state_invariants = build_business_state_invariants(business_flows)
    business_mutation_plans = build_business_mutation_plans(business_flows)
    security_invariants = dedupe_json_records_by_field(
        security_invariants + business_state_invariants,
        "invariant_id",
    )
    safe_manual_test_plans = build_safe_manual_test_plans(
        security_invariants,
        api_endpoint_models=api_endpoint_models,
        actor_model=actor_model,
    )
    oracle_templates = build_oracle_templates(safe_manual_test_plans)
    agent_interfaces = build_agent_interfaces()
    agent_runs = build_deterministic_agent_runs(
        api_endpoint_models=api_endpoint_models,
        parameter_classifications=parameter_classifications,
        dependency_graph=api_dependency_graph,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
        oracle_templates=oracle_templates,
    )
    llm_agent_outputs = build_agent_output_scaffolds(
        api_endpoint_models=api_endpoint_models,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
    )
    api_artifact_index = build_api_artifact_index(
        output_dir=args.output,
        api_endpoint_models=api_endpoint_models,
        traffic=traffic_records,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        parameter_classifications=parameter_classifications,
        schema_diffs=schema_diffs,
        dependency_graph=api_dependency_graph,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        manual_test_plans=safe_manual_test_plans,
        oracle_templates=oracle_templates,
    )
    raw_candidates = dedupe_records(build_basic_candidates(normalized_endpoints))
    verification = verify_candidates(
        raw_candidates,
        config=config,
        endpoints=normalized_endpoints,
        network=False,
    )
    candidates = dedupe_records(verification.candidates)
    filtered_candidates = dedupe_records(verification.filtered)
    params = dedupe_records(build_parameters_from_endpoints(normalized_endpoints))
    findings: list[dict[str, Any]] = []
    ranked = rank_records(candidates)
    clusters = cluster_records(ranked)
    cluster_evidence_packs = build_cluster_evidence_packs(
        clusters,
        ranked,
        config=config,
        filtered=filtered_candidates,
    )
    llm_triage_input_packs = build_llm_triage_input_packs(
        cluster_evidence_packs,
        raw_candidates=raw_candidates,
        reviewable_candidates=candidates,
        filtered_candidates=filtered_candidates,
        api_semantic_map=api_semantic_map,
        api_endpoint_models=api_endpoint_models,
        schema_diffs=schema_diffs,
        api_dependency_graph=api_dependency_graph,
        api_sequences=api_sequences,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
        oracle_templates=oracle_templates,
        actor_model=actor_model,
        graphql_operations=graphql_operations,
        business_flows=business_flows,
        business_mutation_plans=business_mutation_plans,
        config=config,
    )
    args.output.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output / "assets.jsonl", [])
    write_jsonl(args.output / "services.jsonl", [])
    write_jsonl(args.output / "endpoints.jsonl", normalized_endpoints)
    write_jsonl(args.output / "js-files.jsonl", js_files)
    write_jsonl(args.output / "api-docs.jsonl", api_docs)
    write_jsonl(args.output / "graphql-endpoints.jsonl", graphql)
    write_jsonl(args.output / "source-maps.jsonl", source_maps)
    write_jsonl(args.output / "api-semantic-map.jsonl", api_semantic_map)
    write_jsonl(args.output / "traffic.jsonl", traffic_records)
    write_jsonl(args.output / "actors.jsonl", actors)
    write_jsonl(args.output / "actor-relationships.jsonl", actor_relationships)
    write_jsonl(args.output / "owned-resources.jsonl", owned_resources)
    write_jsonl(args.output / "request-schemas.jsonl", request_schemas)
    write_jsonl(args.output / "response-schemas.jsonl", response_schemas)
    write_jsonl(args.output / "api-endpoints.jsonl", api_endpoint_models)
    write_jsonl(args.output / "graphql-operations.jsonl", graphql_operations)
    write_jsonl(args.output / "graphql-logical-endpoints.jsonl", graphql_logical_endpoints)
    write_json(args.output / "api-artifact-index.json", api_artifact_index)
    write_jsonl(args.output / "ui-field-usage.jsonl", ui_field_usage)
    write_jsonl(args.output / "parameter-classification.jsonl", parameter_classifications)
    write_jsonl(args.output / "schema-diff.jsonl", schema_diffs)
    write_json(args.output / "api-dependency-graph.json", api_dependency_graph)
    write_jsonl(args.output / "api-sequences.jsonl", api_sequences)
    write_jsonl(args.output / "state-transitions.jsonl", state_transitions)
    write_jsonl(args.output / "handler-hypotheses.jsonl", handler_hypotheses)
    write_jsonl(args.output / "security-invariants.jsonl", security_invariants)
    write_jsonl(args.output / "business-flows.jsonl", business_flows)
    write_jsonl(args.output / "business-state-invariants.jsonl", business_state_invariants)
    write_jsonl(args.output / "business-mutation-plans.jsonl", business_mutation_plans)
    write_jsonl(args.output / "manual-test-plans.jsonl", safe_manual_test_plans)
    write_jsonl(args.output / "oracle-templates.jsonl", oracle_templates)
    write_json(args.output / "agent-interfaces.json", agent_interfaces)
    write_jsonl(args.output / "agent-runs.jsonl", agent_runs)
    write_jsonl(args.output / "llm-agent-outputs.jsonl", llm_agent_outputs)
    write_jsonl(args.output / "port-services.jsonl", [])
    write_jsonl(args.output / "params.jsonl", params)
    write_jsonl(args.output / "candidates.jsonl", raw_candidates)
    write_jsonl(args.output / "candidates-verified.jsonl", candidates)
    write_jsonl(args.output / "candidates-filtered.jsonl", filtered_candidates)
    write_jsonl(args.output / "findings.jsonl", findings)
    write_jsonl(args.output / "ranked.jsonl", ranked)
    write_jsonl(args.output / "clusters.jsonl", clusters)
    write_jsonl(args.output / "verification-probes.jsonl", verification.probes)
    write_jsonl(args.output / "soft404-baselines.jsonl", verification.soft404_baselines)
    write_json(args.output / "verification-summary.json", verification.summary)
    cluster_pack_dir = args.output / "cluster-evidence-packs"
    for pack in cluster_evidence_packs:
        write_json(cluster_pack_dir / f"{pack['pack_id']}.json", pack)
    write_jsonl(args.output / "cluster-evidence-packs.jsonl", cluster_evidence_packs)
    llm_input_pack_dir = args.output / "llm-triage-input-packs"
    for pack in llm_triage_input_packs:
        write_json(llm_input_pack_dir / f"{pack['pack_id']}.json", pack)
    write_jsonl(args.output / "llm-triage-input-packs.jsonl", llm_triage_input_packs)
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
            "js_files": js_files,
            "api_docs": api_docs,
            "graphql_endpoints": graphql,
            "source_maps": source_maps,
            "api_semantic_map": api_semantic_map,
            "traffic": traffic_records,
            "actors": actors,
            "actor_relationships": actor_relationships,
            "owned_resources": owned_resources,
            "request_schemas": request_schemas,
            "response_schemas": response_schemas,
            "api_endpoint_models": api_endpoint_models,
            "graphql_operations": graphql_operations,
            "graphql_logical_endpoints": graphql_logical_endpoints,
            "api_artifact_index": api_artifact_index,
            "ui_field_usage": ui_field_usage,
            "parameter_classifications": parameter_classifications,
            "schema_diffs": schema_diffs,
            "api_dependency_graph": api_dependency_graph,
            "api_sequences": api_sequences,
            "state_transitions": state_transitions,
            "handler_hypotheses": handler_hypotheses,
            "security_invariants": security_invariants,
            "business_flows": business_flows,
            "business_state_invariants": business_state_invariants,
            "business_mutation_plans": business_mutation_plans,
            "safe_manual_test_plans": safe_manual_test_plans,
            "oracle_templates": oracle_templates,
            "agent_interfaces": agent_interfaces,
            "agent_runs": agent_runs,
            "llm_agent_outputs": llm_agent_outputs,
            "port_services": [],
            "params": params,
            "candidates": raw_candidates,
            "candidates_verified": candidates,
            "candidates_filtered": filtered_candidates,
            "findings": findings,
            "clusters": clusters,
            "verification": verification.summary,
        },
    )
    evidence_paths = write_evidence_notes(ranked, args.output / "evidence")
    payload = {
        "valid": True,
        "profile": args.profile,
        "endpoint_count": len(normalized_endpoints),
        "js_file_count": len(js_files),
        "api_doc_count": len(api_docs),
        "graphql_endpoint_count": len(graphql),
        "source_map_count": len(source_maps),
        "api_semantic_count": len(api_semantic_map),
        "traffic_count": len(traffic_records),
        "actor_count": len(actors),
        "actor_relationship_count": len(actor_relationships),
        "owned_resource_count": len(owned_resources),
        "request_schema_count": len(request_schemas),
        "response_schema_count": len(response_schemas),
        "api_endpoint_model_count": len(api_endpoint_models),
        "graphql_operation_count": len(graphql_operations),
        "graphql_logical_endpoint_count": len(graphql_logical_endpoints),
        "ui_field_usage_count": len(ui_field_usage),
        "parameter_classification_count": len(parameter_classifications),
        "schema_diff_count": len(schema_diffs),
        "dependency_edge_count": len(api_dependency_graph.get("edges") or []),
        "api_sequence_count": len(api_sequences),
        "state_transition_count": len(state_transitions),
        "handler_hypothesis_count": len(handler_hypotheses),
        "security_invariant_count": len(security_invariants),
        "business_flow_count": len(business_flows),
        "business_state_invariant_count": len(business_state_invariants),
        "business_mutation_plan_count": len(business_mutation_plans),
        "safe_manual_test_plan_count": len(safe_manual_test_plans),
        "oracle_template_count": len(oracle_templates),
        "agent_run_count": len(agent_runs),
        "llm_agent_output_count": len(llm_agent_outputs),
        "param_count": len(params),
        "candidate_count": len(raw_candidates),
        "reviewable_candidate_count": len(candidates),
        "filtered_candidate_count": len(filtered_candidates),
        "finding_count": len(findings),
        "ranked_count": len(ranked),
        "cluster_count": len(clusters),
        "cluster_evidence_packs": len(cluster_evidence_packs),
        "llm_triage_input_packs": len(llm_triage_input_packs),
        "supplemental_llm_triage_packs": max(
            0,
            len(llm_triage_input_packs) - len(cluster_evidence_packs),
        ),
        "removed_count": len(removed),
        "evidence_notes": len(evidence_paths),
        "output": str(args.output),
        "assets": 0,
        "services": 0,
        "endpoints": len(normalized_endpoints),
        "js_files": len(js_files),
        "api_docs": len(api_docs),
        "graphql_endpoints": len(graphql),
        "source_maps": len(source_maps),
        "api_semantics": len(api_semantic_map),
        "traffic_records": len(traffic_records),
        "actors": len(actors),
        "actor_relationships": len(actor_relationships),
        "owned_resources": len(owned_resources),
        "request_schemas": len(request_schemas),
        "response_schemas": len(response_schemas),
        "api_endpoint_models": len(api_endpoint_models),
        "graphql_operations": len(graphql_operations),
        "graphql_logical_endpoints": len(graphql_logical_endpoints),
        "ui_field_usage": len(ui_field_usage),
        "parameter_classifications": len(parameter_classifications),
        "schema_diffs": len(schema_diffs),
        "dependency_edges": len(api_dependency_graph.get("edges") or []),
        "api_sequences": len(api_sequences),
        "state_transitions": len(state_transitions),
        "handler_hypotheses": len(handler_hypotheses),
        "security_invariants": len(security_invariants),
        "business_flows": len(business_flows),
        "business_state_invariants": len(business_state_invariants),
        "business_mutation_plans": len(business_mutation_plans),
        "safe_manual_test_plans": len(safe_manual_test_plans),
        "oracle_templates": len(oracle_templates),
        "agent_runs": len(agent_runs),
        "llm_agent_outputs": len(llm_agent_outputs),
        "port_services": 0,
        "params": len(params),
        "candidates": len(raw_candidates),
        "reviewable_candidates": len(candidates),
        "filtered_candidates": len(filtered_candidates),
        "findings": len(findings),
        "ranked": len(ranked),
        "clusters": len(clusters),
        "removed": len(removed),
    }
    write_json(args.output / "summary.json", payload)
    report_markdown = render_markdown_report(
        ranked,
        program=config.program_name,
        profile=args.profile,
        scope_file=str(args.config),
        removed_count=len(removed),
        clusters=clusters,
        summary={
            "assets": 0,
            "services": 0,
            "endpoints": len(normalized_endpoints),
            "js_files": len(js_files),
            "api_docs": len(api_docs),
            "graphql_endpoints": len(graphql),
            "source_maps": len(source_maps),
            "api_semantics": len(api_semantic_map),
            "traffic_records": len(traffic_records),
            "actors": len(actors),
            "actor_relationships": len(actor_relationships),
            "request_schemas": len(request_schemas),
            "response_schemas": len(response_schemas),
            "api_endpoint_models": len(api_endpoint_models),
            "graphql_operations": len(graphql_operations),
            "graphql_logical_endpoints": len(graphql_logical_endpoints),
            "ui_field_usage": len(ui_field_usage),
            "parameter_classifications": len(parameter_classifications),
            "schema_diffs": len(schema_diffs),
            "dependency_edges": len(api_dependency_graph.get("edges") or []),
            "api_sequences": len(api_sequences),
            "state_transitions": len(state_transitions),
            "handler_hypotheses": len(handler_hypotheses),
            "security_invariants": len(security_invariants),
            "business_flows": len(business_flows),
            "business_state_invariants": len(business_state_invariants),
            "business_mutation_plans": len(business_mutation_plans),
            "safe_manual_test_plans": len(safe_manual_test_plans),
            "oracle_templates": len(oracle_templates),
            "agent_runs": len(agent_runs),
            "llm_agent_outputs": len(llm_agent_outputs),
            "port_services": 0,
            "parameters": len(params),
            "scanner_findings": len(findings),
            "raw_candidates": len(raw_candidates),
            "reviewable_candidates": len(candidates),
            "filtered_candidates": len(filtered_candidates),
            "clusters": len(clusters),
        },
        verification_summary=verification.summary,
        api_semantic_map=api_semantic_map,
    )
    (args.output / "report.md").write_text(report_markdown, encoding="utf-8")
    payload["review_artifacts"] = write_review_artifacts(args.output)
    write_json(args.output / "summary.json", payload)
    _print_json(payload)
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


def cmd_clusters_triage(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    records = load_json_records(args.input)
    if len(records) != 1:
        _print_json(
            {
                "triaged": False,
                "error": "cluster triage expects exactly one cluster evidence pack",
                "input_count": len(records),
            }
        )
        return 2
    result = run_cluster_triage(
        records[0],
        config=config,
        llm_config=config.llm,
        driver_name=args.driver,
        allow_external_llm=args.allow_external_llm,
    )
    payload = {
        "triaged": result.llm_status == "succeeded",
        "policy": report.to_dict(),
        "result": result.to_dict(),
    }
    if args.output:
        write_json(args.output, payload)
    _print_json(payload)
    return 0 if result.llm_status in {"succeeded", "not_submitted"} else 3


def cmd_review_summary(args: argparse.Namespace) -> int:
    summary = build_run_review_summary(args.run_dir)
    queue = build_review_queue(
        args.run_dir,
        include_filtered=args.include_filtered,
        limit=args.limit,
    )
    triage_queue = build_llm_triage_queue(args.run_dir, limit=args.limit)
    if args.markdown:
        text = render_run_review_markdown(summary, queue, triage_queue)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
        print(text)
        return 0
    payload = {"summary": summary, "queue": queue, "llm_triage_queue": triage_queue}
    if args.output:
        write_json(args.output, payload)
    _print_json(payload)
    return 0


def cmd_review_queue(args: argparse.Namespace) -> int:
    queue = build_review_queue(
        args.run_dir,
        include_filtered=args.include_filtered,
        limit=args.limit,
    )
    if args.output:
        write_json(args.output, queue)
    _print_json(queue)
    return 0


def cmd_review_debug(args: argparse.Namespace) -> int:
    text = render_verification_debug_markdown(args.run_dir, limit=args.limit)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text)
    return 0


def cmd_review_triage_queue(args: argparse.Namespace) -> int:
    queue = build_llm_triage_queue(args.run_dir, limit=args.limit)
    if args.output:
        write_json(args.output, queue)
    _print_json(queue)
    return 0


def cmd_review_write(args: argparse.Namespace) -> int:
    artifacts = write_review_artifacts(args.run_dir, limit=args.limit)
    _print_json({"written": True, "artifacts": artifacts})
    return 0


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


def cmd_capture_har(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config)
    report = build_policy_report(config, allow_risky=args.allow_risky)
    if not report.valid:
        _print_json({"valid": False, "policy": report.to_dict()})
        return 2
    if args.from_har:
        result = write_har_capture_artifacts(
            har_path=args.from_har,
            output_dir=args.output,
            config=config,
            target=args.target,
            actor=args.actor,
            role=args.role,
            tenant=args.tenant,
            state=args.state,
            flow=args.flow,
            label=args.label,
        )
    else:
        result = capture_har_session(
            target=args.target,
            output_dir=args.output,
            config=config,
            actor=args.actor,
            role=args.role,
            tenant=args.tenant,
            state=args.state,
            flow=args.flow,
            label=args.label,
            headed=not args.headless,
        )
    _print_json({"valid": True, "policy": report.to_dict(), "result": result})
    return 0 if result.get("captured") else 3


def cmd_analyze_graphql(args: argparse.Namespace) -> int:
    traffic = load_json_records(args.traffic)
    operations = build_graphql_operation_models(traffic)
    logical_endpoints = build_graphql_logical_endpoint_models(operations)
    classifications = build_graphql_parameter_classifications(operations)
    write_jsonl(args.operations_output, operations)
    if args.logical_endpoints_output:
        write_jsonl(args.logical_endpoints_output, logical_endpoints)
    if args.parameter_classification_output:
        write_jsonl(args.parameter_classification_output, classifications)
    _print_json(
        {
            "modeled": True,
            "operation_count": len(operations),
            "logical_endpoint_count": len(logical_endpoints),
            "parameter_classification_count": len(classifications),
            "operations_output": str(args.operations_output),
            "logical_endpoints_output": str(args.logical_endpoints_output)
            if args.logical_endpoints_output
            else None,
            "parameter_classification_output": str(args.parameter_classification_output)
            if args.parameter_classification_output
            else None,
        }
    )
    return 0


def cmd_analyze_websocket(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config) if args.config else None
    records = load_json_records(args.input)
    messages, logical_endpoints, removed = build_websocket_message_models(records, config=config)
    write_jsonl(args.output, messages)
    if args.logical_endpoints_output:
        write_jsonl(args.logical_endpoints_output, logical_endpoints)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "modeled": True,
            "message_count": len(messages),
            "logical_endpoint_count": len(logical_endpoints),
            "removed_count": len(removed),
            "output": str(args.output),
        }
    )
    return 0


def cmd_analyze_sse(args: argparse.Namespace) -> int:
    config = load_scope_config(args.config) if args.config else None
    records = load_json_records(args.input)
    events, logical_endpoints, removed = build_sse_event_models(records, config=config)
    write_jsonl(args.output, events)
    if args.logical_endpoints_output:
        write_jsonl(args.logical_endpoints_output, logical_endpoints)
    if args.removed_output:
        write_json(args.removed_output, removed)
    _print_json(
        {
            "modeled": True,
            "event_count": len(events),
            "logical_endpoint_count": len(logical_endpoints),
            "removed_count": len(removed),
            "output": str(args.output),
        }
    )
    return 0


def cmd_feedback_build(args: argparse.Namespace) -> int:
    feedback = load_json_records(args.feedback)
    dependency_graph = (
        json.loads(args.dependency_graph.read_text(encoding="utf-8"))
        if args.dependency_graph
        else {}
    )
    state_transitions = load_json_records(args.state_transitions) if args.state_transitions else []
    graph, updates = build_feedback_graph(
        feedback,
        dependency_graph=dependency_graph,
        state_transitions=state_transitions,
    )
    write_json(args.output, graph)
    if args.oracle_updates_output:
        write_jsonl(args.oracle_updates_output, updates)
    _print_json(
        {
            "built": True,
            "feedback_count": len(feedback),
            "node_count": len(graph.get("nodes") or []),
            "edge_count": len(graph.get("edges") or []),
            "oracle_update_count": len(updates),
            "output": str(args.output),
        }
    )
    return 0


def cmd_agents_interfaces(args: argparse.Namespace) -> int:
    interfaces = build_agent_interfaces()
    if args.output:
        write_json(args.output, interfaces)
    _print_json(interfaces)
    return 0


def cmd_agents_run(args: argparse.Namespace) -> int:
    api_endpoints = load_json_records(args.api_endpoints) if args.api_endpoints else []
    parameter_classifications = (
        load_json_records(args.parameter_classifications) if args.parameter_classifications else []
    )
    dependency_graph = (
        json.loads(args.dependency_graph.read_text(encoding="utf-8"))
        if args.dependency_graph
        else {}
    )
    handler_hypotheses = (
        load_json_records(args.handler_hypotheses) if args.handler_hypotheses else []
    )
    security_invariants = (
        load_json_records(args.security_invariants) if args.security_invariants else []
    )
    manual_test_plans = load_json_records(args.manual_test_plans) if args.manual_test_plans else []
    oracle_templates = load_json_records(args.oracle_templates) if args.oracle_templates else []
    report_drafts = load_json_records(args.report_drafts) if args.report_drafts else []
    runs = build_deterministic_agent_runs(
        api_endpoint_models=api_endpoints,
        parameter_classifications=parameter_classifications,
        dependency_graph=dependency_graph,
        handler_hypotheses=handler_hypotheses,
        security_invariants=security_invariants,
        safe_manual_test_plans=manual_test_plans,
        oracle_templates=oracle_templates,
        report_drafts=report_drafts,
    )
    write_jsonl(args.output, runs)
    _print_json({"ran": True, "agent_run_count": len(runs), "output": str(args.output)})
    return 0


def dedupe_json_records_by_field(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        value = str(record.get(field) or "")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(record)
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="donzo")
    parser.add_argument("--version", action="version", version="donzo 0.3.0")
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
    tools_check_parser.add_argument(
        "--profile",
        choices=["fast", "normal", "deep"],
        default="fast",
    )
    tools_check_parser.add_argument("tools", nargs="*")
    tools_check_parser.set_defaults(func=cmd_tools_check)

    tools_matrix_parser = tools_subparsers.add_parser(
        "matrix",
        help="Print profile-aware required and optional recon tool matrix",
    )
    tools_matrix_parser.set_defaults(func=cmd_tools_matrix)

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
    doctor_parser.add_argument("--profile", choices=["fast", "normal", "deep"])
    doctor_parser.add_argument("--allow-risky", action="store_true")
    doctor_parser.set_defaults(func=cmd_doctor)

    run_parser = subparsers.add_parser("run", help="Run a DONZO recon pipeline")
    run_parser.add_argument("-c", "--config", type=Path, required=True)
    run_parser.add_argument("-p", "--profile", choices=["fast", "normal", "deep"], default="fast")
    run_parser.add_argument("-o", "--output", type=Path, required=True)
    run_parser.add_argument("--execute", action="store_true")
    run_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable stderr progress bars during --execute runs",
    )
    run_parser.add_argument(
        "--progress-mode",
        choices=["auto", "in-place", "plain"],
        default="auto",
        help="Progress rendering mode for --execute runs",
    )
    run_parser.add_argument(
        "--llm-triage",
        action="store_true",
        help="Run configured LLM cluster triage after deterministic verification",
    )
    run_parser.add_argument(
        "--no-llm-triage",
        action="store_true",
        help="Disable default LLM cluster triage even when llm.required=true",
    )
    run_parser.add_argument(
        "--llm-driver",
        choices=["auto", "codex_cli", "openai", "anthropic"],
        default="auto",
        help="LLM driver for --llm-triage",
    )
    run_parser.add_argument(
        "--llm-limit",
        type=int,
        default=0,
        help="Maximum cluster evidence packs submitted to LLM triage; 0 means all",
    )
    run_parser.add_argument(
        "--allow-external-llm",
        action="store_true",
        help="Allow the configured LLM driver to make an external call",
    )
    run_parser.add_argument(
        "--no-external-llm",
        action="store_true",
        help="Disable default external LLM calls even when llm.required=true",
    )
    run_parser.add_argument(
        "--compare-to",
        type=Path,
        help="Write run-diff artifacts against a previous DONZO run directory",
    )
    run_parser.add_argument(
        "--har",
        type=Path,
        action="append",
        help="Add local HAR traffic to endpoint/schema modeling artifacts",
    )
    run_parser.add_argument(
        "--actors",
        type=Path,
        action="append",
        help="Add actor/account model JSON or JSONL with safe credential references",
    )
    run_parser.add_argument("--traffic-actor", default="unknown")
    run_parser.add_argument("--traffic-role", default="")
    run_parser.add_argument("--traffic-tenant", default="")
    run_parser.add_argument("--traffic-state", default="unknown")
    run_parser.add_argument("--traffic-flow", default="")
    run_parser.add_argument("--traffic-label", default="")
    run_parser.add_argument("--allow-risky", action="store_true")
    run_parser.set_defaults(func=cmd_run)

    capture_har_parser = subparsers.add_parser(
        "capture-har",
        help="Record or ingest a user-driven HAR flow with redacted DONZO artifacts",
    )
    capture_har_parser.add_argument("-c", "--config", type=Path, required=True)
    capture_har_parser.add_argument("--target", required=True)
    capture_har_parser.add_argument("-o", "--output", type=Path, required=True)
    capture_har_parser.add_argument("--actor", default="unknown")
    capture_har_parser.add_argument("--role", default="")
    capture_har_parser.add_argument("--tenant", default="")
    capture_har_parser.add_argument("--state", default="unknown")
    capture_har_parser.add_argument("--flow", default="manual_flow")
    capture_har_parser.add_argument("--label", default="")
    capture_har_parser.add_argument("--from-har", type=Path)
    capture_har_parser.add_argument("--headless", action="store_true")
    capture_har_parser.add_argument("--allow-risky", action="store_true")
    capture_har_parser.set_defaults(func=cmd_capture_har)

    ingest_har_parser = subparsers.add_parser(
        "ingest-har",
        help="Convert local HAR files into redacted DONZO traffic/schema artifacts",
    )
    ingest_har_parser.add_argument("-c", "--config", type=Path, required=True)
    ingest_har_parser.add_argument("-i", "--input", type=Path, action="append", required=True)
    ingest_har_parser.add_argument("--actors", type=Path, action="append")
    ingest_har_parser.add_argument("--actor", default="unknown")
    ingest_har_parser.add_argument("--role", default="")
    ingest_har_parser.add_argument("--tenant", default="")
    ingest_har_parser.add_argument("--state", default="unknown")
    ingest_har_parser.add_argument("--flow", default="")
    ingest_har_parser.add_argument("--label", default="")
    ingest_har_parser.add_argument("--source", default="har")
    ingest_har_parser.add_argument("-o", "--output", type=Path)
    ingest_har_parser.add_argument("--endpoints-output", type=Path)
    ingest_har_parser.add_argument("--request-schemas-output", type=Path)
    ingest_har_parser.add_argument("--response-schemas-output", type=Path)
    ingest_har_parser.add_argument("--actors-output", type=Path)
    ingest_har_parser.add_argument("--actor-relationships-output", type=Path)
    ingest_har_parser.add_argument("--owned-resources-output", type=Path)
    ingest_har_parser.add_argument("--api-endpoints-output", type=Path)
    ingest_har_parser.add_argument("--graphql-operations-output", type=Path)
    ingest_har_parser.add_argument("--graphql-logical-endpoints-output", type=Path)
    ingest_har_parser.add_argument("--api-artifact-index-output", type=Path)
    ingest_har_parser.add_argument("--ui-field-usage-output", type=Path)
    ingest_har_parser.add_argument("--parameter-classification-output", type=Path)
    ingest_har_parser.add_argument("--schema-diff-output", type=Path)
    ingest_har_parser.add_argument("--api-dependency-graph-output", type=Path)
    ingest_har_parser.add_argument("--api-sequences-output", type=Path)
    ingest_har_parser.add_argument("--state-transitions-output", type=Path)
    ingest_har_parser.add_argument("--handler-hypotheses-output", type=Path)
    ingest_har_parser.add_argument("--security-invariants-output", type=Path)
    ingest_har_parser.add_argument("--business-flows-output", type=Path)
    ingest_har_parser.add_argument("--business-state-invariants-output", type=Path)
    ingest_har_parser.add_argument("--business-mutation-plans-output", type=Path)
    ingest_har_parser.add_argument("--manual-test-plans-output", type=Path)
    ingest_har_parser.add_argument("--oracle-templates-output", type=Path)
    ingest_har_parser.add_argument("--agent-interfaces-output", type=Path)
    ingest_har_parser.add_argument("--agent-runs-output", type=Path)
    ingest_har_parser.add_argument("--llm-agent-outputs-output", type=Path)
    ingest_har_parser.add_argument("--removed-output", type=Path)
    ingest_har_parser.add_argument("--allow-risky", action="store_true")
    ingest_har_parser.set_defaults(func=cmd_ingest_har)

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

    analyze_parser = subparsers.add_parser("analyze", help="Analyze local static artifacts")
    analyze_subparsers = analyze_parser.add_subparsers(dest="analyze_command", required=True)

    analyze_js_parser = analyze_subparsers.add_parser(
        "js",
        help="Extract endpoint candidates from a local JavaScript file",
    )
    analyze_js_parser.add_argument("-c", "--config", type=Path, required=True)
    analyze_js_parser.add_argument("-i", "--input", type=Path, required=True)
    analyze_js_parser.add_argument("--base-url", required=True)
    analyze_js_parser.add_argument("-o", "--output", type=Path)
    analyze_js_parser.add_argument("--candidates-output", type=Path)
    analyze_js_parser.add_argument("--removed-output", type=Path)
    analyze_js_parser.add_argument("--source", default="js_static")
    analyze_js_parser.add_argument("--allow-risky", action="store_true")
    analyze_js_parser.set_defaults(func=cmd_analyze_js)

    analyze_openapi_parser = analyze_subparsers.add_parser(
        "openapi",
        help="Extract endpoint candidates from a local OpenAPI JSON document",
    )
    analyze_openapi_parser.add_argument("-c", "--config", type=Path, required=True)
    analyze_openapi_parser.add_argument("-i", "--input", type=Path, required=True)
    analyze_openapi_parser.add_argument("--base-url", required=True)
    analyze_openapi_parser.add_argument("-o", "--output", type=Path)
    analyze_openapi_parser.add_argument("--candidates-output", type=Path)
    analyze_openapi_parser.add_argument("--removed-output", type=Path)
    analyze_openapi_parser.add_argument("--source", default="openapi")
    analyze_openapi_parser.add_argument("--allow-risky", action="store_true")
    analyze_openapi_parser.set_defaults(func=cmd_analyze_openapi)

    analyze_collection_parser = analyze_subparsers.add_parser(
        "collection",
        help="Extract endpoint candidates from a local Postman or Insomnia JSON export",
    )
    analyze_collection_parser.add_argument("-c", "--config", type=Path, required=True)
    analyze_collection_parser.add_argument("-i", "--input", type=Path, required=True)
    analyze_collection_parser.add_argument("--base-url", default="")
    analyze_collection_parser.add_argument("-o", "--output", type=Path)
    analyze_collection_parser.add_argument("--candidates-output", type=Path)
    analyze_collection_parser.add_argument("--removed-output", type=Path)
    analyze_collection_parser.add_argument("--source", default="api_collection")
    analyze_collection_parser.add_argument("--allow-risky", action="store_true")
    analyze_collection_parser.set_defaults(func=cmd_analyze_collection)

    analyze_graphql_parser = analyze_subparsers.add_parser(
        "graphql",
        help="Model GraphQL operations from redacted DONZO traffic JSON/JSONL",
    )
    analyze_graphql_parser.add_argument("--traffic", type=Path, required=True)
    analyze_graphql_parser.add_argument("--operations-output", type=Path, required=True)
    analyze_graphql_parser.add_argument("--logical-endpoints-output", type=Path)
    analyze_graphql_parser.add_argument("--parameter-classification-output", type=Path)
    analyze_graphql_parser.set_defaults(func=cmd_analyze_graphql)

    analyze_websocket_parser = analyze_subparsers.add_parser(
        "websocket",
        help="Model WebSocket message JSON/JSONL artifacts",
    )
    analyze_websocket_parser.add_argument("-c", "--config", type=Path)
    analyze_websocket_parser.add_argument("-i", "--input", type=Path, required=True)
    analyze_websocket_parser.add_argument("-o", "--output", type=Path, required=True)
    analyze_websocket_parser.add_argument("--logical-endpoints-output", type=Path)
    analyze_websocket_parser.add_argument("--removed-output", type=Path)
    analyze_websocket_parser.set_defaults(func=cmd_analyze_websocket)

    analyze_sse_parser = analyze_subparsers.add_parser(
        "sse",
        help="Model Server-Sent Events JSON/JSONL artifacts",
    )
    analyze_sse_parser.add_argument("-c", "--config", type=Path)
    analyze_sse_parser.add_argument("-i", "--input", type=Path, required=True)
    analyze_sse_parser.add_argument("-o", "--output", type=Path, required=True)
    analyze_sse_parser.add_argument("--logical-endpoints-output", type=Path)
    analyze_sse_parser.add_argument("--removed-output", type=Path)
    analyze_sse_parser.set_defaults(func=cmd_analyze_sse)

    auth_parser = subparsers.add_parser("auth", help="Authenticated crawl helper commands")
    auth_subparsers = auth_parser.add_subparsers(dest="auth_command", required=True)
    auth_check_parser = auth_subparsers.add_parser(
        "check",
        help="Check auth crawl env readiness without printing secrets",
    )
    auth_check_parser.add_argument("-c", "--config", type=Path, required=True)
    auth_check_parser.add_argument("--target", default="")
    auth_check_parser.add_argument("--allow-risky", action="store_true")
    auth_check_parser.set_defaults(func=cmd_auth_check)
    auth_template_parser = auth_subparsers.add_parser(
        "template",
        help="Print safe shell env templates for authenticated crawling",
    )
    auth_template_parser.add_argument("-c", "--config", type=Path, required=True)
    auth_template_parser.set_defaults(func=cmd_auth_template)

    diff_parser = subparsers.add_parser("diff", help="Compare two DONZO run directories")
    diff_parser.add_argument("--previous", type=Path, required=True)
    diff_parser.add_argument("--current", type=Path, required=True)
    diff_parser.add_argument("-o", "--output", type=Path)
    diff_parser.set_defaults(func=cmd_diff)

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

    clusters_parser = subparsers.add_parser("clusters", help="Cluster evidence commands")
    clusters_subparsers = clusters_parser.add_subparsers(
        dest="clusters_command",
        required=True,
    )
    clusters_triage_parser = clusters_subparsers.add_parser(
        "triage",
        help="Run Codex CLI triage for one cluster evidence pack",
    )
    clusters_triage_parser.add_argument("-c", "--config", type=Path, required=True)
    clusters_triage_parser.add_argument("-i", "--input", type=Path, required=True)
    clusters_triage_parser.add_argument("-o", "--output", type=Path)
    clusters_triage_parser.add_argument(
        "--driver",
        choices=["auto", "openai", "anthropic", "codex_cli"],
        default="auto",
    )
    clusters_triage_parser.add_argument("--allow-risky", action="store_true")
    clusters_triage_parser.add_argument("--allow-external-llm", action="store_true")
    clusters_triage_parser.set_defaults(func=cmd_clusters_triage)

    review_parser = subparsers.add_parser("review", help="Inspect DONZO run outputs")
    review_subparsers = review_parser.add_subparsers(dest="review_command", required=True)

    review_summary_parser = review_subparsers.add_parser(
        "summary",
        help="Summarize a run directory for human review",
    )
    review_summary_parser.add_argument("-r", "--run-dir", type=Path, required=True)
    review_summary_parser.add_argument("-o", "--output", type=Path)
    review_summary_parser.add_argument("--markdown", action="store_true")
    review_summary_parser.add_argument("--include-filtered", action="store_true")
    review_summary_parser.add_argument("--limit", type=int, default=10)
    review_summary_parser.set_defaults(func=cmd_review_summary)

    review_queue_parser = review_subparsers.add_parser(
        "queue",
        help="Print manual-review queue entries from a run directory",
    )
    review_queue_parser.add_argument("-r", "--run-dir", type=Path, required=True)
    review_queue_parser.add_argument("-o", "--output", type=Path)
    review_queue_parser.add_argument("--include-filtered", action="store_true")
    review_queue_parser.add_argument("--limit", type=int, default=20)
    review_queue_parser.set_defaults(func=cmd_review_queue)

    review_debug_parser = review_subparsers.add_parser(
        "debug",
        help="Render verification filter debug Markdown for a run directory",
    )
    review_debug_parser.add_argument("-r", "--run-dir", type=Path, required=True)
    review_debug_parser.add_argument("-o", "--output", type=Path)
    review_debug_parser.add_argument("--limit", type=int, default=10)
    review_debug_parser.set_defaults(func=cmd_review_debug)

    review_triage_queue_parser = review_subparsers.add_parser(
        "triage-queue",
        help="Print cluster LLM triage commands for a run directory",
    )
    review_triage_queue_parser.add_argument("-r", "--run-dir", type=Path, required=True)
    review_triage_queue_parser.add_argument("-o", "--output", type=Path)
    review_triage_queue_parser.add_argument("--limit", type=int, default=20)
    review_triage_queue_parser.set_defaults(func=cmd_review_triage_queue)

    review_write_parser = review_subparsers.add_parser(
        "write",
        help="Write review.md, verification-debug.md, and triage queue artifacts",
    )
    review_write_parser.add_argument("-r", "--run-dir", type=Path, required=True)
    review_write_parser.add_argument("--limit", type=int, default=10)
    review_write_parser.set_defaults(func=cmd_review_write)

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

    oracle_parser = subparsers.add_parser("oracle", help="Manual oracle result commands")
    oracle_subparsers = oracle_parser.add_subparsers(dest="oracle_command", required=True)
    oracle_evaluate_parser = oracle_subparsers.add_parser(
        "evaluate",
        help="Evaluate manual oracle results against safe DONZO oracle templates",
    )
    oracle_evaluate_parser.add_argument("--test-plans", type=Path, required=True)
    oracle_evaluate_parser.add_argument("--oracle-templates", type=Path, required=True)
    oracle_evaluate_parser.add_argument("--manual-results", type=Path, required=True)
    oracle_evaluate_parser.add_argument("-o", "--output", type=Path, required=True)
    oracle_evaluate_parser.add_argument("--evidence-output", type=Path)
    oracle_evaluate_parser.set_defaults(func=cmd_oracle_evaluate)

    feedback_parser = subparsers.add_parser(
        "feedback",
        help="Build manual execution feedback graph artifacts",
    )
    feedback_subparsers = feedback_parser.add_subparsers(dest="feedback_command", required=True)
    feedback_build_parser = feedback_subparsers.add_parser(
        "build",
        help="Build feedback graph from human-entered manual observations",
    )
    feedback_build_parser.add_argument("--feedback", type=Path, required=True)
    feedback_build_parser.add_argument("--dependency-graph", type=Path)
    feedback_build_parser.add_argument("--state-transitions", type=Path)
    feedback_build_parser.add_argument("-o", "--output", type=Path, required=True)
    feedback_build_parser.add_argument("--oracle-updates-output", type=Path)
    feedback_build_parser.set_defaults(func=cmd_feedback_build)

    agents_parser = subparsers.add_parser(
        "agents",
        help="Deterministic structured agent interfaces",
    )
    agents_subparsers = agents_parser.add_subparsers(dest="agents_command", required=True)
    agents_interfaces_parser = agents_subparsers.add_parser(
        "interfaces",
        help="Print deterministic agent interface contracts",
    )
    agents_interfaces_parser.add_argument("-o", "--output", type=Path)
    agents_interfaces_parser.set_defaults(func=cmd_agents_interfaces)
    agents_run_parser = agents_subparsers.add_parser(
        "run-deterministic",
        help="Run deterministic agent interface checks over local artifacts",
    )
    agents_run_parser.add_argument("--api-endpoints", type=Path)
    agents_run_parser.add_argument("--parameter-classifications", type=Path)
    agents_run_parser.add_argument("--dependency-graph", type=Path)
    agents_run_parser.add_argument("--handler-hypotheses", type=Path)
    agents_run_parser.add_argument("--security-invariants", type=Path)
    agents_run_parser.add_argument("--manual-test-plans", type=Path)
    agents_run_parser.add_argument("--oracle-templates", type=Path)
    agents_run_parser.add_argument("--report-drafts", type=Path)
    agents_run_parser.add_argument("-o", "--output", type=Path, required=True)
    agents_run_parser.set_defaults(func=cmd_agents_run)

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

    report_from_oracle_parser = report_subparsers.add_parser(
        "from-oracle",
        help=(
            "Generate deterministic report drafts and regression cases "
            "from confirmed oracle results"
        ),
    )
    report_from_oracle_parser.add_argument("--oracle-results", type=Path, required=True)
    report_from_oracle_parser.add_argument("--test-plans", type=Path)
    report_from_oracle_parser.add_argument("--security-invariants", type=Path)
    report_from_oracle_parser.add_argument("--api-endpoints", type=Path)
    report_from_oracle_parser.add_argument("--drafts-output", type=Path, required=True)
    report_from_oracle_parser.add_argument("--regression-output", type=Path)
    report_from_oracle_parser.add_argument("--markdown-output", type=Path)
    report_from_oracle_parser.set_defaults(func=cmd_report_from_oracle)

    run_fixture_parser = subparsers.add_parser(
        "run-fixture",
        help="Run the local fixture MVP pipeline without network recon",
    )
    run_fixture_parser.add_argument("-c", "--config", type=Path, required=True)
    run_fixture_parser.add_argument(
        "-p",
        "--profile",
        choices=["fast", "normal", "deep"],
        default="fast",
    )
    run_fixture_parser.add_argument("--endpoints", type=Path, required=True)
    run_fixture_parser.add_argument("--archive-urls", type=Path)
    run_fixture_parser.add_argument("--js-file", type=Path)
    run_fixture_parser.add_argument("--js-base-url")
    run_fixture_parser.add_argument("--openapi", type=Path)
    run_fixture_parser.add_argument("--openapi-base-url")
    run_fixture_parser.add_argument("--har", type=Path, action="append")
    run_fixture_parser.add_argument("--actors", type=Path, action="append")
    run_fixture_parser.add_argument("--traffic-actor", default="unknown")
    run_fixture_parser.add_argument("--traffic-role", default="")
    run_fixture_parser.add_argument("--traffic-tenant", default="")
    run_fixture_parser.add_argument("--traffic-state", default="unknown")
    run_fixture_parser.add_argument("--traffic-flow", default="")
    run_fixture_parser.add_argument("--traffic-label", default="")
    run_fixture_parser.add_argument("-o", "--output", type=Path, required=True)
    run_fixture_parser.add_argument("--allow-risky", action="store_true")
    run_fixture_parser.set_defaults(func=cmd_run_fixture)

    return parser


def main(argv: list[str] | None = None) -> int:
    load_project_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
