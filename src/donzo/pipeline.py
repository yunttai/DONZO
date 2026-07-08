from __future__ import annotations

import json
import os
import shutil
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

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
from donzo.analyzers.discovery import (
    endpoints_from_robots_text,
    endpoints_from_sitemap_text,
)
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
from donzo.analyzers.openapi import (
    COMMON_APP_BASE_PATHS,
    OPENAPI_SCHEMA_PATHS,
    api_surface_candidates,
    endpoint_base_urls,
    endpoints_from_openapi_document,
    openapi_document_candidates,
    openapi_url,
    parse_openapi_document_text,
)
from donzo.analyzers.parameter_classifier import build_parameter_classifications
from donzo.analyzers.schema_diff import build_schema_diffs
from donzo.analyzers.semantics import build_api_semantic_map, summarize_semantic_map
from donzo.analyzers.technology import build_technology_inferences
from donzo.analyzers.ui_field_usage import build_ui_field_usage
from donzo.auth import auth_summary, auth_tool_header_args
from donzo.candidates.basic import build_basic_candidates
from donzo.clustering import cluster_records
from donzo.config import ScopeConfig
from donzo.dedupe import dedupe_records
from donzo.evidence import write_evidence_notes
from donzo.llm_triage.agent_interfaces import build_agent_interfaces, build_deterministic_agent_runs
from donzo.llm_triage.agent_outputs import build_agent_output_scaffolds
from donzo.llm_triage.stages import run_cluster_triage
from donzo.models import now_utc, stable_id
from donzo.normalize.artifacts import (
    normalize_asset_lines,
    normalize_endpoint_lines,
    normalize_endpoint_records,
    normalize_finding_records,
    normalize_httpx_records,
    normalize_port_records,
    normalize_secret_scan_records,
)
from donzo.oracles.oracle_templates import build_oracle_templates
from donzo.parameters import build_parameters_from_endpoints
from donzo.planning.test_plans import build_safe_manual_test_plans
from donzo.ranking import rank_records
from donzo.reporting.markdown import render_markdown_report
from donzo.review import write_review_artifacts
from donzo.runner import CommandPlan, CommandResult, build_command_plan, run_command_plan
from donzo.state import build_run_state, transition_run_state, write_run_state
from donzo.storage.jsonl import (
    load_jsonl_text,
    load_text_lines,
    write_json,
    write_jsonl,
)
from donzo.tools import check_tools, is_required_for_profile, tool_binary
from donzo.traffic.har_ingest import endpoint_records_from_traffic, ingest_har_files
from donzo.verification import build_cluster_evidence_packs, verify_candidates
from donzo.verification.probe import probe_url

ProgressCallback = Callable[[dict[str, Any]], None]

PIPELINE_PROGRESS_STEPS = (
    "scope / preflight",
    "recon commands",
    "parse artifacts",
    "analyze endpoints",
    "candidate generation",
    "verification / filtering",
    "rank / cluster / evidence",
    "write report",
)

ASSET_DISCOVERY_COMMANDS = {"subfinder", "amass", "bbot", "uncover", "alterx"}
ARCHIVE_URL_COMMANDS = {"gau", "waybackurls", "waymore", "paramspider"}


def run_fast_pipeline(
    *,
    config: ScopeConfig,
    output_dir: Path,
    execute: bool = False,
) -> dict[str, Any]:
    return run_recon_pipeline(
        config=config,
        output_dir=output_dir,
        profile="fast",
        execute=execute,
    )


def run_recon_pipeline(
    *,
    config: ScopeConfig,
    output_dir: Path,
    profile: str = "fast",
    execute: bool = False,
    progress_callback: ProgressCallback | None = None,
    llm_triage: bool = False,
    llm_driver: str = "auto",
    llm_limit: int = 5,
    allow_external_llm: bool = False,
    compare_to: Path | None = None,
    har_inputs: list[Path] | None = None,
    actor_inputs: list[Path] | None = None,
    traffic_actor: str = "unknown",
    traffic_role: str = "",
    traffic_tenant: str = "",
    traffic_state: str = "unknown",
    traffic_flow: str = "",
    traffic_label: str = "",
) -> dict[str, Any]:
    if profile not in {"fast", "normal", "deep"}:
        raise ValueError("only fast, normal, and deep profiles are implemented")
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    normalized_dir = output_dir / "normalized"
    derived_dir = output_dir / "derived"
    plan = build_recon_command_plans(
        config=config,
        output_dir=output_dir,
        profile=profile,
        dry_run=not execute,
    )
    tool_preflight = build_tool_preflight(plan, profile=profile)
    emit_progress(
        progress_callback,
        {
            "event": "plan_ready",
            "profile": profile,
            "execute": execute,
            "plans": [item.to_dict() for item in plan],
            "tool_preflight": tool_preflight,
            "pipeline_steps": build_pipeline_progress_steps(tool_preflight),
        },
    )
    write_json(output_dir / "tool-preflight.json", tool_preflight)
    state = build_run_state(
        program=config.program_name,
        scope_file=str(config.source_path),
        profile=profile,
        execute=execute,
        output_dir=output_dir,
        plans=plan,
        tool_preflight=tool_preflight,
    )
    write_run_state(output_dir, state)
    if not execute:
        payload = {
            "profile": profile,
            "execute": False,
            "tool_preflight": tool_preflight,
            "plans": [item.to_dict() for item in plan],
        }
        write_json(output_dir / "plan.json", payload)
        state = transition_run_state(
            state,
            status="planned",
            phase="dry_run",
            counters={"planned_commands": len(plan)},
            completed=True,
        )
        write_run_state(output_dir, state)
        emit_progress(
            progress_callback,
            {"event": "completed", "profile": profile, "execute": False},
        )
        return payload

    missing = list(tool_preflight["missing"])
    if missing:
        payload = {
            "profile": profile,
            "execute": True,
            "error": "missing_required_tools",
            "tool_preflight": tool_preflight,
            "plans": [item.to_dict() for item in plan],
        }
        write_json(output_dir / "run-error.json", payload)
        state = transition_run_state(
            state,
            status="blocked",
            phase="preflight",
            counters={"missing_tools": len(missing), "planned_commands": len(plan)},
            error="missing_required_tools",
            completed=True,
        )
        write_run_state(output_dir, state)
        emit_progress(
            progress_callback,
            {
                "event": "blocked",
                "profile": profile,
                "error": "missing_required_tools",
                "missing": missing,
            },
        )
        return payload

    state = write_phase_state(
        output_dir,
        state,
        phase="command_execution",
        counters={"planned_commands": len(plan)},
    )
    write_root_domains_file(root_domains(config), derived_dir / "root_domains.txt")
    write_candidate_assets_file(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_http_probe_asset_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_archive_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    optional_skips = optional_skipped_tools(tool_preflight)
    required_by_name = required_tool_name_map(tool_preflight)
    if profile == "deep":
        results = run_deep_recon_commands_parallel(
            plan=plan,
            config=config,
            raw_dir=raw_dir,
            derived_dir=derived_dir,
            optional_skips=optional_skips,
            required_by_name=required_by_name,
            progress_callback=progress_callback,
        )
    else:
        results = run_recon_commands_sequential(
            plan=plan,
            config=config,
            profile=profile,
            raw_dir=raw_dir,
            derived_dir=derived_dir,
            optional_skips=optional_skips,
            required_by_name=required_by_name,
            progress_callback=progress_callback,
        )

    emit_progress(progress_callback, {"event": "normalization_started", "profile": profile})
    state = write_phase_state(
        output_dir,
        state,
        phase="parse_artifacts",
        counters={"completed_commands": len(results)},
    )
    assets = []
    services = []
    endpoints = []
    findings = []
    port_services = []
    traffic_records: list[dict[str, Any]] = []
    request_schemas: list[dict[str, Any]] = []
    response_schemas: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for asset_path, source in (
        (raw_dir / "subfinder.txt", "subfinder"),
        (raw_dir / "dnsx.txt", "dnsx"),
        (raw_dir / "amass.txt", "amass"),
        (raw_dir / "bbot.txt", "bbot"),
        (raw_dir / "uncover.txt", "uncover"),
        (raw_dir / "alterx.txt", "alterx"),
    ):
        if asset_path.exists():
            asset_records, removed_assets = normalize_asset_lines(
                load_text_lines(asset_path),
                config=config,
                source=source,
            )
            assets.extend(asset_records)
            removed.extend(removed_assets)
    httpx_records, httpx_parse_removed = load_tool_json_records(raw_dir / "httpx.jsonl", "httpx")
    removed.extend(httpx_parse_removed)
    if httpx_records:
        services, removed_services = normalize_httpx_records(
            httpx_records,
            config=config,
        )
        removed.extend(removed_services)
        endpoints, removed_endpoints = normalize_endpoint_records(
            httpx_records,
            config=config,
            source="httpx",
        )
        removed.extend(removed_endpoints)
    katana_records, katana_parse_removed = load_tool_json_records(
        raw_dir / "katana.jsonl",
        "katana",
    )
    removed.extend(katana_parse_removed)
    if katana_records:
        katana_endpoints, katana_removed = normalize_endpoint_records(
            katana_records,
            config=config,
            source="katana",
        )
        endpoints.extend(katana_endpoints)
        removed.extend(katana_removed)
    tlsx_records, tlsx_parse_removed = load_tool_json_records(raw_dir / "tlsx.jsonl", "tlsx")
    removed.extend(tlsx_parse_removed)
    if tlsx_records:
        tlsx_assets, tlsx_asset_removed = normalize_asset_lines(
            asset_lines_from_json_records(tlsx_records),
            config=config,
            source="tlsx",
        )
        assets.extend(tlsx_assets)
        removed.extend(tlsx_asset_removed)
        tlsx_ports, tlsx_port_removed = normalize_port_records(
            port_records_from_json_records(tlsx_records, default_port=443),
            config=config,
            source="tlsx",
        )
        port_services.extend(tlsx_ports)
        services.extend(tlsx_ports)
        removed.extend(tlsx_port_removed)
    for archive_path, source in (
        (raw_dir / "gau.txt", "gau"),
        (raw_dir / "waybackurls.txt", "waybackurls"),
        (raw_dir / "waymore.txt", "waymore"),
        (raw_dir / "paramspider.txt", "paramspider"),
        (raw_dir / "qsreplace.txt", "qsreplace"),
        (raw_dir / "arjun.txt", "arjun"),
    ):
        if archive_path.exists():
            archive_endpoints, archive_removed = normalize_endpoint_lines(
                load_text_lines(archive_path),
                config=config,
                source=source,
            )
            endpoints.extend(archive_endpoints)
            removed.extend(archive_removed)
    naabu_records, naabu_parse_removed = load_tool_json_records(raw_dir / "naabu.jsonl", "naabu")
    removed.extend(naabu_parse_removed)
    if naabu_records:
        port_services, port_removed = normalize_port_records(
            naabu_records,
            config=config,
        )
        services.extend(port_services)
        removed.extend(port_removed)
    nuclei_records, nuclei_parse_removed = load_tool_json_records(
        raw_dir / "nuclei.jsonl",
        "nuclei",
    )
    removed.extend(nuclei_parse_removed)
    if nuclei_records:
        findings, removed_findings = normalize_finding_records(
            nuclei_records,
            config=config,
        )
        removed.extend(removed_findings)
    gitleaks_records, gitleaks_parse_removed = load_tool_json_document_records(
        raw_dir / "gitleaks.json",
        "gitleaks",
    )
    removed.extend(gitleaks_parse_removed)
    if gitleaks_records:
        gitleaks_findings, gitleaks_removed = normalize_secret_scan_records(
            gitleaks_records,
            source="gitleaks",
        )
        findings.extend(gitleaks_findings)
        removed.extend(gitleaks_removed)
    trufflehog_records, trufflehog_parse_removed = load_tool_json_records(
        raw_dir / "trufflehog.jsonl",
        "trufflehog",
    )
    removed.extend(trufflehog_parse_removed)
    if trufflehog_records:
        trufflehog_findings, trufflehog_removed = normalize_secret_scan_records(
            trufflehog_records,
            source="trufflehog",
        )
        findings.extend(trufflehog_findings)
        removed.extend(trufflehog_removed)
    kiterunner_records, kiterunner_parse_removed = load_tool_json_records(
        raw_dir / "kiterunner.jsonl",
        "kiterunner",
    )
    removed.extend(kiterunner_parse_removed)
    if kiterunner_records:
        kiterunner_endpoints, kiterunner_removed = normalize_endpoint_records(
            kiterunner_records,
            config=config,
            source="kiterunner",
        )
        endpoints.extend(kiterunner_endpoints)
        removed.extend(kiterunner_removed)
    if har_inputs:
        traffic_records, request_schemas, response_schemas, traffic_removed = ingest_har_files(
            har_inputs,
            config=config,
            actor=traffic_actor,
            role=traffic_role,
            tenant=traffic_tenant,
            state=traffic_state,
            flow=traffic_flow,
            label=traffic_label,
            source="har",
        )
        traffic_endpoints, traffic_endpoint_removed = normalize_endpoint_records(
            endpoint_records_from_traffic(traffic_records),
            config=config,
            source="har",
        )
        endpoints.extend(traffic_endpoints)
        removed.extend(traffic_removed)
        removed.extend(traffic_endpoint_removed)

    assets = dedupe_records(assets)
    port_services = dedupe_records(port_services)
    services = dedupe_records(services)
    endpoints = dedupe_records(endpoints)
    actor_model = build_actor_model(load_actor_records(actor_inputs), traffic=traffic_records)
    actors = actor_model.get("actors") or []
    actor_relationships = actor_model.get("relationships") or []
    owned_resources = actor_model.get("owned_resources") or []
    flow_manifest = flow_manifest_from_traffic(traffic_records)
    emit_pipeline_step_finished(progress_callback, "parse artifacts")
    emit_pipeline_step_started(progress_callback, "analyze endpoints")
    state = write_phase_state(
        output_dir,
        state,
        phase="analyze_endpoints",
        counters={
            "assets": len(assets),
            "services": len(services),
            "endpoints": len(endpoints),
            "removed": len(removed),
        },
    )

    js_files = js_file_endpoints(endpoints)
    if profile in {"normal", "deep"} and execute and config.verification.network_probe:
        declared_endpoints, declared_removed = discover_declared_site_endpoints(
            endpoints,
            config=config,
        )
        endpoints = dedupe_records(endpoints + declared_endpoints)
        removed.extend(declared_removed)
        js_network_endpoints, js_network_removed = discover_js_static_endpoints(
            js_files,
            config=config,
        )
        endpoints = dedupe_records(endpoints + js_network_endpoints)
        removed.extend(js_network_removed)
    if profile in {"normal", "deep"}:
        api_surface_endpoints, api_surface_removed = api_surface_candidates(
            endpoints,
            config=config,
        )
        endpoints = dedupe_records(endpoints + api_surface_endpoints)
        removed.extend(api_surface_removed)
        api_discovery_endpoints, api_discovery_removed = openapi_document_candidates(
            endpoints,
            config=config,
        )
        endpoints = dedupe_records(endpoints + api_discovery_endpoints)
        removed.extend(api_discovery_removed)
        if execute and config.verification.network_probe and config.verification.api_docs.enabled:
            openapi_network_endpoints, openapi_network_docs, openapi_network_removed = (
                discover_openapi_schema_endpoints(endpoints, config=config)
            )
            endpoints = dedupe_records(endpoints + openapi_network_endpoints + openapi_network_docs)
            removed.extend(openapi_network_removed)
    js_files = js_file_endpoints(endpoints)
    if profile in {"normal", "deep"}:
        source_maps, source_map_removed = source_map_endpoints(js_files, config=config)
        endpoints = dedupe_records(endpoints + source_maps)
        removed.extend(source_map_removed)
    else:
        source_maps = []
    js_files = js_file_endpoints(endpoints)
    api_docs = api_doc_endpoints(endpoints)
    graphql = graphql_endpoints(endpoints)
    declared = declared_site_endpoints(endpoints)
    technology_inferences = build_technology_inferences(
        services=services,
        endpoints=endpoints,
        tlsx_records=tlsx_records,
    )
    api_semantic_map = build_api_semantic_map(
        endpoints,
        config=config,
        technology_inferences=technology_inferences,
    )
    api_endpoint_models = build_api_endpoint_models(
        endpoints,
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
    security_invariants = dedupe_by_field(
        security_invariants + business_state_invariants,
        "invariant_id",
    )
    safe_manual_test_plans = build_safe_manual_test_plans(
        security_invariants,
        api_endpoint_models=api_endpoint_models,
        actor_model=actor_model,
    )
    oracle_templates = build_oracle_templates(safe_manual_test_plans)
    api_artifact_index = build_api_artifact_index(
        output_dir=output_dir,
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
    params = dedupe_records(build_parameters_from_endpoints(endpoints))
    emit_pipeline_step_finished(progress_callback, "analyze endpoints")
    emit_pipeline_step_started(progress_callback, "candidate generation")
    state = write_phase_state(
        output_dir,
        state,
        phase="candidate_generation",
        counters={
            "endpoints": len(endpoints),
            "js_files": len(js_files),
            "api_docs": len(api_docs),
            "graphql_endpoints": len(graphql),
            "source_maps": len(source_maps),
            "declared_endpoints": len(declared),
            "technology_inferences": len(technology_inferences),
            "api_semantics": len(api_semantic_map),
            "api_endpoint_models": len(api_endpoint_models),
            "traffic_records": len(traffic_records),
            "request_schemas": len(request_schemas),
            "response_schemas": len(response_schemas),
            "actors": len(actors),
            "actor_relationships": len(actor_relationships),
            "flow_manifest": len(flow_manifest),
            "graphql_operations": len(graphql_operations),
            "graphql_logical_endpoints": len(graphql_logical_endpoints),
            "parameter_classifications": len(parameter_classifications),
            "schema_diffs": len(schema_diffs),
            "ui_field_usage": len(ui_field_usage),
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
            "params": len(params),
            "removed": len(removed),
        },
    )
    raw_candidates = dedupe_records(build_basic_candidates(endpoints))
    emit_pipeline_step_finished(progress_callback, "candidate generation")
    emit_pipeline_step_started(progress_callback, "verification / filtering")
    state = write_phase_state(
        output_dir,
        state,
        phase="verification_filtering",
        counters={
            "raw_candidates": len(raw_candidates),
            "endpoints": len(endpoints),
            "network_probe": bool(execute and config.verification.network_probe),
        },
    )

    def handle_verification_progress(event: dict[str, Any]) -> None:
        nonlocal state
        emit_progress(progress_callback, event)
        state = write_phase_state(
            output_dir,
            state,
            phase="verification_filtering",
            counters={
                "raw_candidates": len(raw_candidates),
                "endpoints": len(endpoints),
                "network_probe": bool(execute and config.verification.network_probe),
                "processed_candidates": int(event.get("processed") or 0),
                "total_candidates": int(event.get("total") or 0),
                "probe_used": int(event.get("probe_used") or 0),
                "probe_limit": int(event.get("probe_limit") or 0),
                "filtered_candidates": int(event.get("filtered") or 0),
                "reviewable_candidates": int(event.get("reviewable") or 0),
                "origin_timeout_cached": int(event.get("origin_timeout_cached") or 0),
                "origin_timeout_count": int(event.get("origin_timeout_count") or 0),
            },
        )

    verification = verify_candidates(
        raw_candidates,
        config=config,
        endpoints=endpoints,
        network=execute and config.verification.network_probe,
        progress_callback=handle_verification_progress,
    )
    candidates = dedupe_records(verification.candidates)
    filtered_candidates = dedupe_records(verification.filtered)
    if execute:
        api_docs = confirmed_api_doc_endpoints(api_docs, candidates)
    emit_pipeline_step_finished(progress_callback, "verification / filtering")
    emit_pipeline_step_started(progress_callback, "rank / cluster / evidence")
    state = write_phase_state(
        output_dir,
        state,
        phase="rank_cluster_evidence",
        counters={
            "reviewable_candidates": len(candidates),
            "filtered_candidates": len(filtered_candidates),
            "findings": len(findings),
            "network_probe_budget": verification.summary.get("network_probe_budget"),
        },
    )
    findings = dedupe_records(findings)
    ranked = rank_records(candidates + findings)
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
        technology_inferences=technology_inferences,
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
    llm_agent_outputs = build_agent_output_scaffolds(
        api_endpoint_models=api_endpoint_models,
        security_invariants=security_invariants,
        safe_manual_test_plans=safe_manual_test_plans,
    )
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
    evidence_paths = write_evidence_notes(ranked, output_dir / "evidence")
    emit_pipeline_step_finished(progress_callback, "rank / cluster / evidence")
    emit_pipeline_step_started(progress_callback, "write report")
    state = write_phase_state(
        output_dir,
        state,
        phase="write_report",
        counters={
            "ranked": len(ranked),
            "clusters": len(clusters),
            "evidence_notes": len(evidence_paths),
        },
    )
    normalized_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(normalized_dir / "assets.jsonl", assets)
    write_jsonl(normalized_dir / "services.jsonl", services)
    write_jsonl(normalized_dir / "endpoints.jsonl", endpoints)
    write_jsonl(normalized_dir / "js-files.jsonl", js_files)
    write_jsonl(normalized_dir / "api-docs.jsonl", api_docs)
    write_jsonl(normalized_dir / "graphql-endpoints.jsonl", graphql)
    write_jsonl(normalized_dir / "source-maps.jsonl", source_maps)
    write_jsonl(normalized_dir / "declared-endpoints.jsonl", declared)
    write_jsonl(normalized_dir / "technology-inference.jsonl", technology_inferences)
    write_jsonl(normalized_dir / "api-semantic-map.jsonl", api_semantic_map)
    write_jsonl(normalized_dir / "traffic.jsonl", traffic_records)
    write_jsonl(normalized_dir / "flow-manifest.jsonl", flow_manifest)
    write_jsonl(normalized_dir / "actors.jsonl", actors)
    write_jsonl(normalized_dir / "actor-relationships.jsonl", actor_relationships)
    write_jsonl(normalized_dir / "owned-resources.jsonl", owned_resources)
    write_jsonl(normalized_dir / "request-schemas.jsonl", request_schemas)
    write_jsonl(normalized_dir / "response-schemas.jsonl", response_schemas)
    write_jsonl(normalized_dir / "api-endpoints.jsonl", api_endpoint_models)
    write_jsonl(normalized_dir / "graphql-operations.jsonl", graphql_operations)
    write_jsonl(normalized_dir / "graphql-logical-endpoints.jsonl", graphql_logical_endpoints)
    write_json(normalized_dir / "api-artifact-index.json", api_artifact_index)
    write_jsonl(normalized_dir / "ui-field-usage.jsonl", ui_field_usage)
    write_jsonl(normalized_dir / "parameter-classification.jsonl", parameter_classifications)
    write_jsonl(normalized_dir / "schema-diff.jsonl", schema_diffs)
    write_json(normalized_dir / "api-dependency-graph.json", api_dependency_graph)
    write_jsonl(normalized_dir / "api-sequences.jsonl", api_sequences)
    write_jsonl(normalized_dir / "state-transitions.jsonl", state_transitions)
    write_jsonl(normalized_dir / "handler-hypotheses.jsonl", handler_hypotheses)
    write_jsonl(normalized_dir / "security-invariants.jsonl", security_invariants)
    write_jsonl(normalized_dir / "business-flows.jsonl", business_flows)
    write_jsonl(normalized_dir / "business-state-invariants.jsonl", business_state_invariants)
    write_jsonl(normalized_dir / "business-mutation-plans.jsonl", business_mutation_plans)
    write_jsonl(normalized_dir / "manual-test-plans.jsonl", safe_manual_test_plans)
    write_jsonl(normalized_dir / "oracle-templates.jsonl", oracle_templates)
    write_json(normalized_dir / "agent-interfaces.json", agent_interfaces)
    write_jsonl(normalized_dir / "agent-runs.jsonl", agent_runs)
    write_jsonl(normalized_dir / "llm-agent-outputs.jsonl", llm_agent_outputs)
    write_jsonl(normalized_dir / "port-services.jsonl", port_services)
    write_jsonl(normalized_dir / "params.jsonl", params)
    write_jsonl(normalized_dir / "candidates-raw.jsonl", raw_candidates)
    write_jsonl(normalized_dir / "candidates-verified.jsonl", candidates)
    write_jsonl(normalized_dir / "candidates-filtered.jsonl", filtered_candidates)
    write_jsonl(normalized_dir / "findings.jsonl", findings)
    write_jsonl(output_dir / "assets.jsonl", assets)
    write_jsonl(output_dir / "services.jsonl", services)
    write_jsonl(output_dir / "endpoints.jsonl", endpoints)
    write_jsonl(output_dir / "js-files.jsonl", js_files)
    write_jsonl(output_dir / "api-docs.jsonl", api_docs)
    write_jsonl(output_dir / "graphql-endpoints.jsonl", graphql)
    write_jsonl(output_dir / "source-maps.jsonl", source_maps)
    write_jsonl(output_dir / "declared-endpoints.jsonl", declared)
    write_jsonl(output_dir / "technology-inference.jsonl", technology_inferences)
    write_jsonl(output_dir / "api-semantic-map.jsonl", api_semantic_map)
    write_jsonl(output_dir / "traffic.jsonl", traffic_records)
    write_jsonl(output_dir / "flow-manifest.jsonl", flow_manifest)
    write_jsonl(output_dir / "actors.jsonl", actors)
    write_jsonl(output_dir / "actor-relationships.jsonl", actor_relationships)
    write_jsonl(output_dir / "owned-resources.jsonl", owned_resources)
    write_jsonl(output_dir / "request-schemas.jsonl", request_schemas)
    write_jsonl(output_dir / "response-schemas.jsonl", response_schemas)
    write_jsonl(output_dir / "api-endpoints.jsonl", api_endpoint_models)
    write_jsonl(output_dir / "graphql-operations.jsonl", graphql_operations)
    write_jsonl(output_dir / "graphql-logical-endpoints.jsonl", graphql_logical_endpoints)
    write_json(output_dir / "api-artifact-index.json", api_artifact_index)
    write_jsonl(output_dir / "ui-field-usage.jsonl", ui_field_usage)
    write_jsonl(output_dir / "parameter-classification.jsonl", parameter_classifications)
    write_jsonl(output_dir / "schema-diff.jsonl", schema_diffs)
    write_json(output_dir / "api-dependency-graph.json", api_dependency_graph)
    write_jsonl(output_dir / "api-sequences.jsonl", api_sequences)
    write_jsonl(output_dir / "state-transitions.jsonl", state_transitions)
    write_jsonl(output_dir / "handler-hypotheses.jsonl", handler_hypotheses)
    write_jsonl(output_dir / "security-invariants.jsonl", security_invariants)
    write_jsonl(output_dir / "business-flows.jsonl", business_flows)
    write_jsonl(output_dir / "business-state-invariants.jsonl", business_state_invariants)
    write_jsonl(output_dir / "business-mutation-plans.jsonl", business_mutation_plans)
    write_jsonl(output_dir / "manual-test-plans.jsonl", safe_manual_test_plans)
    write_jsonl(output_dir / "oracle-templates.jsonl", oracle_templates)
    write_json(output_dir / "agent-interfaces.json", agent_interfaces)
    write_jsonl(output_dir / "agent-runs.jsonl", agent_runs)
    write_jsonl(output_dir / "llm-agent-outputs.jsonl", llm_agent_outputs)
    write_jsonl(output_dir / "port-services.jsonl", port_services)
    write_jsonl(output_dir / "params.jsonl", params)
    write_jsonl(output_dir / "candidates.jsonl", raw_candidates)
    write_jsonl(output_dir / "candidates-verified.jsonl", candidates)
    write_jsonl(output_dir / "candidates-filtered.jsonl", filtered_candidates)
    write_jsonl(output_dir / "findings.jsonl", findings)
    write_jsonl(output_dir / "ranked.jsonl", ranked)
    write_jsonl(output_dir / "clusters.jsonl", clusters)
    write_jsonl(output_dir / "verification-probes.jsonl", verification.probes)
    write_jsonl(output_dir / "soft404-baselines.jsonl", verification.soft404_baselines)
    write_json(output_dir / "verification-summary.json", verification.summary)
    cluster_pack_dir = output_dir / "cluster-evidence-packs"
    for pack in cluster_evidence_packs:
        write_json(cluster_pack_dir / f"{pack['pack_id']}.json", pack)
    write_jsonl(output_dir / "cluster-evidence-packs.jsonl", cluster_evidence_packs)
    llm_input_pack_dir = output_dir / "llm-triage-input-packs"
    for pack in llm_triage_input_packs:
        write_json(llm_input_pack_dir / f"{pack['pack_id']}.json", pack)
    write_jsonl(output_dir / "llm-triage-input-packs.jsonl", llm_triage_input_packs)
    write_json(output_dir / "removed-out-of-scope.json", removed)
    write_json(
        output_dir / "recon-result.json",
        {
            "program": config.program_name,
            "scope_file": str(config.source_path),
            "generated_at": now_utc(),
            "assets": assets,
            "services": services,
            "endpoints": endpoints,
            "js_files": js_files,
            "api_docs": api_docs,
            "graphql_endpoints": graphql,
            "source_maps": source_maps,
            "declared_endpoints": declared,
            "technology_inferences": technology_inferences,
            "api_semantic_map": api_semantic_map,
            "traffic": traffic_records,
            "flow_manifest": flow_manifest,
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
            "port_services": port_services,
            "params": params,
            "candidates": raw_candidates,
            "candidates_verified": candidates,
            "candidates_filtered": filtered_candidates,
            "findings": findings,
            "clusters": clusters,
            "verification": verification.summary,
        },
    )
    (output_dir / "report.md").write_text(
        render_markdown_report(
            ranked,
            program=config.program_name,
            profile=profile,
            scope_file=str(config.source_path),
            removed_count=len(removed),
            clusters=clusters,
            summary={
                "assets": len(assets),
                "services": len(services),
                "endpoints": len(endpoints),
                "js_files": len(js_files),
                "api_docs": len(api_docs),
                "graphql_endpoints": len(graphql),
                "source_maps": len(source_maps),
                "declared_endpoints": len(declared),
                "technology_inferences": len(technology_inferences),
                "api_semantics": len(api_semantic_map),
                "traffic_records": len(traffic_records),
                "flow_manifest": len(flow_manifest),
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
                "port_services": len(port_services),
                "parameters": len(params),
                "scanner_findings": len(findings),
                "raw_candidates": len(raw_candidates),
                "reviewable_candidates": len(candidates),
                "filtered_candidates": len(filtered_candidates),
                "clusters": len(clusters),
                "cluster_evidence_packs": len(cluster_evidence_packs),
                "llm_triage_input_packs": len(llm_triage_input_packs),
                "supplemental_llm_triage_packs": max(
                    0,
                    len(llm_triage_input_packs) - len(cluster_evidence_packs),
                ),
            },
            verification_summary=verification.summary,
            technology_inferences=technology_inferences,
            api_semantic_map=api_semantic_map,
        ),
        encoding="utf-8",
    )
    payload = {
        "profile": profile,
        "execute": True,
        "tool_preflight": tool_preflight,
        "results": results,
        "assets": len(assets),
        "services": len(services),
        "endpoints": len(endpoints),
        "js_files": len(js_files),
        "api_docs": len(api_docs),
        "graphql_endpoints": len(graphql),
        "source_maps": len(source_maps),
        "declared_endpoints": len(declared),
        "technology_inferences": len(technology_inferences),
        "api_semantics": len(api_semantic_map),
        "traffic_records": len(traffic_records),
        "flow_manifest": len(flow_manifest),
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
        "port_services": len(port_services),
        "params": len(params),
        "candidates": len(raw_candidates),
        "reviewable_candidates": len(candidates),
        "filtered_candidates": len(filtered_candidates),
        "findings": len(findings),
        "ranked": len(ranked),
        "clusters": len(clusters),
        "removed": len(removed),
        "evidence_notes": len(evidence_paths),
        "output": str(output_dir),
        "auth_crawl": auth_summary(config),
    }
    write_json(output_dir / "summary.json", payload)
    payload["review_artifacts"] = write_review_artifacts(output_dir)
    if llm_triage:
        emit_pipeline_step_started(progress_callback, "LLM triage")
        state = write_phase_state(
            output_dir,
            state,
            phase="llm_triage",
            counters={
                "cluster_evidence_packs": len(cluster_evidence_packs),
                "llm_triage_input_packs": len(llm_triage_input_packs),
            },
        )
        llm_payload = run_llm_triage_artifacts(
            llm_triage_input_packs,
            config=config,
            output_dir=output_dir,
            driver_name=llm_driver,
            limit=llm_limit,
            allow_external_llm=allow_external_llm,
        )
        payload["llm_triage"] = llm_payload["summary"]
        payload["llm_triage_artifacts"] = llm_payload["artifacts"]
        emit_pipeline_step_finished(progress_callback, "LLM triage")
    dashboard_artifacts = write_dashboard_artifacts(output_dir, payload=payload, config=config)
    payload["dashboard_artifacts"] = dashboard_artifacts
    if compare_to:
        diff_payload = build_run_diff(
            compare_to, output_dir, output_path=output_dir / "run-diff.json"
        )
        payload["run_diff"] = diff_payload.get("summary", {})
        payload["run_diff_artifacts"] = {
            "json": str(output_dir / "run-diff.json"),
            "markdown": str(output_dir / "run-diff.md"),
        }
    write_json(output_dir / "summary.json", payload)
    emit_pipeline_step_finished(progress_callback, "write report")
    state = transition_run_state(
        state,
        status="completed",
        phase="done",
        counters={
            "assets": len(assets),
            "services": len(services),
            "endpoints": len(endpoints),
            "js_files": len(js_files),
            "api_docs": len(api_docs),
            "graphql_endpoints": len(graphql),
            "source_maps": len(source_maps),
            "declared_endpoints": len(declared),
            "technology_inferences": len(technology_inferences),
            "api_semantics": len(api_semantic_map),
            "traffic_records": len(traffic_records),
            "request_schemas": len(request_schemas),
            "response_schemas": len(response_schemas),
            "api_endpoint_models": len(api_endpoint_models),
            "ui_field_usage": len(ui_field_usage),
            "parameter_classifications": len(parameter_classifications),
            "schema_diffs": len(schema_diffs),
            "dependency_edges": len(api_dependency_graph.get("edges") or []),
            "api_sequences": len(api_sequences),
            "state_transitions": len(state_transitions),
            "handler_hypotheses": len(handler_hypotheses),
            "security_invariants": len(security_invariants),
            "safe_manual_test_plans": len(safe_manual_test_plans),
            "oracle_templates": len(oracle_templates),
            "llm_agent_outputs": len(llm_agent_outputs),
            "port_services": len(port_services),
            "params": len(params),
            "candidates": len(raw_candidates),
            "reviewable_candidates": len(candidates),
            "filtered_candidates": len(filtered_candidates),
            "findings": len(findings),
            "ranked": len(ranked),
            "clusters": len(clusters),
            "cluster_evidence_packs": len(cluster_evidence_packs),
            "llm_triage_input_packs": len(llm_triage_input_packs),
            "removed": len(removed),
            "evidence_notes": len(evidence_paths),
        },
        artifacts={
            "clusters": str(output_dir / "clusters.jsonl"),
            "cluster_evidence_packs": str(output_dir / "cluster-evidence-packs.jsonl"),
            "llm_triage_input_packs": str(output_dir / "llm-triage-input-packs.jsonl"),
            "llm_agent_outputs": str(output_dir / "llm-agent-outputs.jsonl"),
            "recon_result": str(output_dir / "recon-result.json"),
            "review": str(output_dir / "review.md"),
            "verification_debug": str(output_dir / "verification-debug.md"),
            "llm_triage_queue": str(output_dir / "llm-triage-queue.json"),
            "llm_triage_summary": str(output_dir / "llm-triage-summary.json"),
            "dashboard": str(output_dir / "dashboard.html"),
            "run_diff": str(output_dir / "run-diff.json"),
            "technology_inference": str(output_dir / "technology-inference.jsonl"),
            "api_semantic_map": str(output_dir / "api-semantic-map.jsonl"),
            "traffic": str(output_dir / "traffic.jsonl"),
            "request_schemas": str(output_dir / "request-schemas.jsonl"),
            "response_schemas": str(output_dir / "response-schemas.jsonl"),
            "api_endpoints": str(output_dir / "api-endpoints.jsonl"),
            "api_artifact_index": str(output_dir / "api-artifact-index.json"),
            "ui_field_usage": str(output_dir / "ui-field-usage.jsonl"),
            "parameter_classification": str(output_dir / "parameter-classification.jsonl"),
            "schema_diff": str(output_dir / "schema-diff.jsonl"),
            "api_dependency_graph": str(output_dir / "api-dependency-graph.json"),
            "api_sequences": str(output_dir / "api-sequences.jsonl"),
            "state_transitions": str(output_dir / "state-transitions.jsonl"),
            "handler_hypotheses": str(output_dir / "handler-hypotheses.jsonl"),
            "security_invariants": str(output_dir / "security-invariants.jsonl"),
            "manual_test_plans": str(output_dir / "manual-test-plans.jsonl"),
            "oracle_templates": str(output_dir / "oracle-templates.jsonl"),
        },
        completed=True,
    )
    write_run_state(output_dir, state)
    emit_progress(
        progress_callback,
        {
            "event": "completed",
            "profile": profile,
            "execute": True,
            "output": str(output_dir),
        },
    )
    return payload


def run_recon_commands_sequential(
    *,
    plan: list[CommandPlan],
    config: ScopeConfig,
    profile: str,
    raw_dir: Path,
    derived_dir: Path,
    optional_skips: dict[str, str],
    required_by_name: dict[str, bool],
    progress_callback: ProgressCallback | None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    total = len(plan)
    for index, item in enumerate(plan, start=1):
        emit_command_started(progress_callback, item, index=index, total=total)
        result = execute_recon_command(
            item,
            config=config,
            profile=profile,
            optional_skips=optional_skips,
            required_by_name=required_by_name,
        )
        results.append(result)
        emit_command_finished(progress_callback, item, result, index=index, total=total)
        apply_recon_command_artifact_updates(
            item,
            result,
            config=config,
            raw_dir=raw_dir,
            derived_dir=derived_dir,
        )
    return results


def run_deep_recon_commands_parallel(
    *,
    plan: list[CommandPlan],
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
    optional_skips: dict[str, str],
    required_by_name: dict[str, bool],
    progress_callback: ProgressCallback | None,
) -> list[dict[str, Any]]:
    by_name = {item.name: item for item in plan}
    results_by_name: dict[str, dict[str, Any]] = {}
    total = len(plan)
    counters = {"started": 0, "completed": 0}

    def run_group(
        initial_names: list[str],
        *,
        schedule_after: dict[str, list[str]] | None = None,
    ) -> None:
        schedule_after = schedule_after or {}
        scheduled: set[str] = set()
        pending: dict[Future[dict[str, Any]], CommandPlan] = {}
        dynamic_count = sum(len(items) for items in schedule_after.values())
        max_workers = max(1, min(total, len(initial_names) + dynamic_count))

        def schedule(executor: ThreadPoolExecutor, name: str) -> None:
            if name in scheduled or name in results_by_name:
                return
            item = by_name.get(name)
            if item is None:
                return
            scheduled.add(name)
            counters["started"] += 1
            emit_command_started(
                progress_callback,
                item,
                index=counters["started"],
                total=total,
            )
            pending[
                executor.submit(
                    execute_recon_command,
                    item,
                    config=config,
                    profile="deep",
                    optional_skips=optional_skips,
                    required_by_name=required_by_name,
                )
            ] = item

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for name in initial_names:
                schedule(executor, name)
            while pending:
                done, _not_done = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    item = pending.pop(future)
                    result = future.result()
                    results_by_name[item.name] = result
                    counters["completed"] += 1
                    emit_command_finished(
                        progress_callback,
                        item,
                        result,
                        index=counters["completed"],
                        total=total,
                    )
                    apply_recon_command_artifact_updates(
                        item,
                        result,
                        config=config,
                        raw_dir=raw_dir,
                        derived_dir=derived_dir,
                    )
                    for next_name in schedule_after.get(item.name, []):
                        schedule(executor, next_name)

    run_group(
        ["subfinder", "amass", "bbot", "uncover"],
        schedule_after={"subfinder": ["alterx"]},
    )
    write_candidate_assets_file(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_http_probe_asset_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    run_group(
        ["dnsx", "tlsx", "gau", "waybackurls", "waymore", "paramspider"],
        schedule_after={"dnsx": ["httpx"]},
    )
    write_archive_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    run_group(["naabu", "qsreplace", "katana", "arjun", "kiterunner", "nuclei"])
    run_group(["kxss"])
    run_group(["gitleaks", "trufflehog"])

    return [results_by_name[item.name] for item in plan if item.name in results_by_name]


def execute_recon_command(
    item: CommandPlan,
    *,
    config: ScopeConfig,
    profile: str,
    optional_skips: dict[str, str],
    required_by_name: dict[str, bool],
) -> dict[str, Any]:
    required_for_run = required_by_name.get(item.name, False)
    runtime_skip_reason = optional_skips.get(item.name) or optional_runtime_skip_reason(
        item,
        required_for_run=required_for_run,
    )
    if runtime_skip_reason:
        return {
            **CommandResult(
                plan=item,
                returncode=None,
                error=None,
            ).to_dict(),
            "skipped": True,
            "skip_reason": runtime_skip_reason,
        }
    result = run_command_plan(
        item,
        execute=True,
        timeout_seconds=command_timeout_seconds(
            item.name,
            profile=profile,
            config=config,
            required_for_run=required_for_run,
        ),
        timeout_error=command_timeout_error(item.name),
    ).to_dict()
    return normalize_optional_command_failure(result, required_for_run=required_for_run)


def emit_command_started(
    callback: ProgressCallback | None,
    item: CommandPlan,
    *,
    index: int,
    total: int,
) -> None:
    emit_progress(
        callback,
        {
            "event": "command_started",
            "index": index,
            "total": total,
            "name": item.name,
            "output_path": str(item.output_path),
        },
    )


def emit_command_finished(
    callback: ProgressCallback | None,
    item: CommandPlan,
    result: dict[str, Any],
    *,
    index: int,
    total: int,
) -> None:
    emit_progress(
        callback,
        {
            "event": "command_finished",
            "index": index,
            "total": total,
            "name": item.name,
            "output_path": str(item.output_path),
            "returncode": result.get("returncode"),
            "error": result.get("error"),
            "skipped": result.get("skipped", False),
            "skip_reason": result.get("skip_reason"),
        },
    )


def apply_recon_command_artifact_updates(
    item: CommandPlan,
    result: dict[str, Any],
    *,
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
) -> None:
    if result.get("skipped"):
        return
    if item.name == "httpx":
        write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    if item.name == "dnsx":
        write_http_probe_asset_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    if item.name in ASSET_DISCOVERY_COMMANDS:
        write_candidate_assets_file(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    if item.name in ARCHIVE_URL_COMMANDS:
        write_archive_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
        write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)


def build_llm_triage_input_packs(
    cluster_evidence_packs: list[dict[str, Any]],
    *,
    raw_candidates: list[dict[str, Any]],
    reviewable_candidates: list[dict[str, Any]],
    filtered_candidates: list[dict[str, Any]],
    technology_inferences: list[dict[str, Any]] | None = None,
    api_semantic_map: list[dict[str, Any]] | None = None,
    api_endpoint_models: list[dict[str, Any]] | None = None,
    schema_diffs: list[dict[str, Any]] | None = None,
    api_dependency_graph: dict[str, Any] | None = None,
    api_sequences: list[dict[str, Any]] | None = None,
    handler_hypotheses: list[dict[str, Any]] | None = None,
    security_invariants: list[dict[str, Any]] | None = None,
    safe_manual_test_plans: list[dict[str, Any]] | None = None,
    oracle_templates: list[dict[str, Any]] | None = None,
    actor_model: dict[str, Any] | None = None,
    graphql_operations: list[dict[str, Any]] | None = None,
    business_flows: list[dict[str, Any]] | None = None,
    business_mutation_plans: list[dict[str, Any]] | None = None,
    config: ScopeConfig,
) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for pack in cluster_evidence_packs:
        enriched = dict(pack)
        enriched.setdefault("pack_kind", "reviewable_cluster")
        enriched.setdefault("triage_source", "candidates-verified.jsonl")
        enriched.setdefault(
            "candidate_context",
            {
                "raw_candidates": len(raw_candidates),
                "reviewable_candidates": len(reviewable_candidates),
                "filtered_candidates": len(filtered_candidates),
                "technology_inferences": len(technology_inferences or []),
                "api_semantics": len(api_semantic_map or []),
                "api_endpoint_models": len(api_endpoint_models or []),
                "schema_diffs": len(schema_diffs or []),
                "dependency_edges": len((api_dependency_graph or {}).get("edges") or []),
                "api_sequences": len(api_sequences or []),
                "handler_hypotheses": len(handler_hypotheses or []),
                "security_invariants": len(security_invariants or []),
                "safe_manual_test_plans": len(safe_manual_test_plans or []),
                "oracle_templates": len(oracle_templates or []),
                "actors": len((actor_model or {}).get("actors") or []),
                "graphql_operations": len(graphql_operations or []),
                "business_flows": len(business_flows or []),
                "business_mutation_plans": len(business_mutation_plans or []),
            },
        )
        enriched.setdefault(
            "technology_context", top_technology_context(technology_inferences or [])
        )
        enriched.setdefault(
            "api_semantic_context", top_api_semantic_context(api_semantic_map or [])
        )
        enriched.setdefault("api_model_context", top_api_model_context(api_endpoint_models or []))
        enriched.setdefault("schema_diff_context", top_schema_diff_context(schema_diffs or []))
        enriched.setdefault(
            "api_reasoning_context",
            top_api_reasoning_context(
                api_dependency_graph=api_dependency_graph or {},
                api_sequences=api_sequences or [],
                handler_hypotheses=handler_hypotheses or [],
                security_invariants=security_invariants or [],
                safe_manual_test_plans=safe_manual_test_plans or [],
                oracle_templates=oracle_templates or [],
            ),
        )
        enriched.setdefault("actor_context", (actor_model or {}).get("summary", {}))
        enriched.setdefault("graphql_context", top_graphql_context(graphql_operations or []))
        enriched.setdefault(
            "business_context",
            top_business_context(business_flows or [], business_mutation_plans or []),
        )
        packs.append(enriched)

    packs.extend(
        build_filtered_candidate_recheck_packs(
            raw_candidates=raw_candidates,
            reviewable_candidates=reviewable_candidates,
            filtered_candidates=filtered_candidates,
            technology_inferences=technology_inferences or [],
            api_semantic_map=api_semantic_map or [],
            api_endpoint_models=api_endpoint_models or [],
            schema_diffs=schema_diffs or [],
            config=config,
        )
    )
    packs.extend(
        build_technology_inference_packs(
            technology_inferences or [],
            raw_candidates=raw_candidates,
            reviewable_candidates=reviewable_candidates,
            filtered_candidates=filtered_candidates,
            api_semantic_map=api_semantic_map or [],
            api_endpoint_models=api_endpoint_models or [],
            schema_diffs=schema_diffs or [],
            config=config,
        )
    )
    packs.extend(
        build_api_semantic_packs(
            api_semantic_map or [],
            raw_candidates=raw_candidates,
            reviewable_candidates=reviewable_candidates,
            filtered_candidates=filtered_candidates,
            technology_inferences=technology_inferences or [],
            api_endpoint_models=api_endpoint_models or [],
            schema_diffs=schema_diffs or [],
            config=config,
        )
    )
    return dedupe_packs_by_id(packs)


def build_filtered_candidate_recheck_packs(
    *,
    raw_candidates: list[dict[str, Any]],
    reviewable_candidates: list[dict[str, Any]],
    filtered_candidates: list[dict[str, Any]],
    technology_inferences: list[dict[str, Any]],
    api_semantic_map: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    config: ScopeConfig,
) -> list[dict[str, Any]]:
    if not filtered_candidates:
        return []
    ranked_filtered = rank_records(filtered_candidates)
    filtered_clusters = cluster_records(ranked_filtered)
    packs = build_cluster_evidence_packs(
        filtered_clusters,
        ranked_filtered,
        config=config,
        filtered=filtered_candidates,
    )
    output: list[dict[str, Any]] = []
    for pack in packs:
        cluster = pack.get("cluster") if isinstance(pack.get("cluster"), dict) else {}
        record_ids = list(cluster.get("record_ids") or [])
        enriched = dict(pack)
        enriched["pack_id"] = stable_id(
            "filtered_candidate_recheck",
            cluster.get("cluster_id"),
            record_ids,
        )
        enriched["pack_kind"] = "filtered_candidate_recheck"
        enriched["triage_source"] = "candidates-filtered.jsonl"
        enriched["candidate_context"] = {
            "raw_candidates": len(raw_candidates),
            "reviewable_candidates": len(reviewable_candidates),
            "filtered_candidates": len(filtered_candidates),
            "technology_inferences": len(technology_inferences),
            "api_semantics": len(api_semantic_map),
            "api_endpoint_models": len(api_endpoint_models),
            "schema_diffs": len(schema_diffs),
            "source": "deterministic_filter_recheck",
        }
        enriched["technology_context"] = top_technology_context(technology_inferences)
        enriched["api_semantic_context"] = top_api_semantic_context(api_semantic_map)
        enriched["api_model_context"] = top_api_model_context(api_endpoint_models)
        enriched["schema_diff_context"] = top_schema_diff_context(schema_diffs)
        enriched["task"] = (
            "Re-check filtered raw candidates for false-negative risk. Prefer IGNORE or "
            "likely_false_positive when deterministic evidence supports the filter reason. "
            "Recommend manual review only when the filter may have removed a meaningful "
            "in-scope candidate. Do not claim exploitation."
        )
        enriched["safety_constraints"] = {
            "automatic_exploit": False,
            "destructive_testing": False,
            "secret_validation": False,
            "takeover_claim": False,
        }
        output.append(enriched)
    return output


def build_technology_inference_packs(
    technology_inferences: list[dict[str, Any]],
    *,
    raw_candidates: list[dict[str, Any]],
    reviewable_candidates: list[dict[str, Any]],
    filtered_candidates: list[dict[str, Any]],
    api_semantic_map: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    config: ScopeConfig,
) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for inference in technology_inferences[:10]:
        origin = str(inference.get("origin") or "")
        if not origin:
            continue
        pack_id = stable_id("technology_inference_pack", origin, inference.get("inference_id"))
        packs.append(
            {
                "stage": "cluster_triage",
                "pack_id": pack_id,
                "pack_kind": "technology_inference_context",
                "triage_source": "technology-inference.jsonl",
                "program": config.program_name,
                "scope_file": str(config.source_path),
                "cluster": {
                    "cluster_id": stable_id("technology_cluster", origin),
                    "cluster_type": "TECHNOLOGY_INFERENCE",
                    "title": (
                        f"Passive technology/API inference on {inference.get('host') or origin}"
                    ),
                    "priority": "P3",
                    "risk_score": 20,
                    "targets": [origin],
                    "representative_target": origin,
                    "count": 1,
                },
                "candidate_count": 0,
                "candidate_context": {
                    "raw_candidates": len(raw_candidates),
                    "reviewable_candidates": len(reviewable_candidates),
                    "filtered_candidates": len(filtered_candidates),
                    "technology_inferences": len(technology_inferences),
                    "api_semantics": len(api_semantic_map),
                    "api_endpoint_models": len(api_endpoint_models),
                    "schema_diffs": len(schema_diffs),
                },
                "api_semantic_context": top_api_semantic_context(api_semantic_map),
                "api_model_context": top_api_model_context(api_endpoint_models),
                "schema_diff_context": top_schema_diff_context(schema_diffs),
                "technology_inference": inference,
                "safety_constraints": {
                    "automatic_exploit": False,
                    "destructive_testing": False,
                    "secret_validation": False,
                    "takeover_claim": False,
                },
                "task": (
                    "Use this passive technology/API inference only as context for "
                    "manual recon prioritization. Do not convert weak fingerprints into "
                    "confirmed findings unless evidence supports a safe manual-review "
                    "candidate."
                ),
            }
        )
    return packs


def build_api_semantic_packs(
    api_semantic_map: list[dict[str, Any]],
    *,
    raw_candidates: list[dict[str, Any]],
    reviewable_candidates: list[dict[str, Any]],
    filtered_candidates: list[dict[str, Any]],
    technology_inferences: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
    schema_diffs: list[dict[str, Any]],
    config: ScopeConfig,
) -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for semantic in api_semantic_map:
        target = str(semantic.get("url") or "")
        if not target:
            continue
        pack_id = stable_id("api_semantic_pack", semantic.get("semantic_id"), target)
        packs.append(
            {
                "stage": "cluster_triage",
                "pack_id": pack_id,
                "pack_kind": "api_semantic_context",
                "triage_source": "api-semantic-map.jsonl",
                "program": config.program_name,
                "scope_file": str(config.source_path),
                "cluster": {
                    "cluster_id": stable_id("api_semantic_cluster", target),
                    "cluster_type": "API_SEMANTIC_INFERENCE",
                    "title": (
                        f"{semantic.get('action', 'action')} "
                        f"{semantic.get('resource', 'resource')} semantic inference"
                    ),
                    "priority": "P3",
                    "risk_score": semantic.get("risk_weight", 20),
                    "targets": [target],
                    "representative_target": target,
                    "count": 1,
                },
                "candidate_count": 0,
                "candidate_context": {
                    "raw_candidates": len(raw_candidates),
                    "reviewable_candidates": len(reviewable_candidates),
                    "filtered_candidates": len(filtered_candidates),
                    "technology_inferences": len(technology_inferences),
                    "api_semantics": len(api_semantic_map),
                    "api_endpoint_models": len(api_endpoint_models),
                    "schema_diffs": len(schema_diffs),
                },
                "api_semantic": semantic,
                "technology_context": top_technology_context(technology_inferences),
                "api_model_context": top_api_model_context(api_endpoint_models),
                "schema_diff_context": top_schema_diff_context(schema_diffs),
                "safety_constraints": {
                    "automatic_exploit": False,
                    "destructive_testing": False,
                    "secret_validation": False,
                    "takeover_claim": False,
                },
                "task": (
                    "Use this API semantic inference to prioritize manual authorization, "
                    "workflow, object ownership, and data exposure review. Do not claim "
                    "a vulnerability without verified behavior."
                ),
            }
        )
    return packs


def top_technology_context(
    technology_inferences: list[dict[str, Any]],
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for item in technology_inferences[:limit]:
        context.append(
            {
                "origin": item.get("origin"),
                "confidence": item.get("confidence"),
                "technologies": (item.get("technologies") or [])[:8],
                "api_hints": (item.get("api_hints") or [])[:8],
            }
        )
    return context


def top_api_semantic_context(
    api_semantic_map: list[dict[str, Any]],
    *,
    limit: int = 15,
) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for item in api_semantic_map[:limit]:
        context.append(
            {
                "url": item.get("url"),
                "method": item.get("method"),
                "resource": item.get("resource"),
                "action": item.get("action"),
                "auth_guess": item.get("auth_guess"),
                "object_id_params": item.get("object_id_params", [])[:8],
                "risk_weight": item.get("risk_weight"),
                "risk_questions": item.get("risk_questions", [])[:5],
            }
        )
    return context


def top_api_model_context(
    api_endpoint_models: list[dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for item in api_endpoint_models[:limit]:
        context.append(
            {
                "endpoint_id": item.get("endpoint_id"),
                "method": item.get("method"),
                "origin": item.get("origin"),
                "path_template": item.get("path_template"),
                "resource": item.get("resource"),
                "action": item.get("action"),
                "operation_type": item.get("operation_type"),
                "auth_required": item.get("auth_required"),
                "path_params": (item.get("path_params") or [])[:8],
                "query_params": (item.get("query_params") or [])[:8],
                "risk_tags": (item.get("risk_tags") or [])[:8],
            }
        )
    return context


def top_schema_diff_context(
    schema_diffs: list[dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    context: list[dict[str, Any]] = []
    for item in schema_diffs[:limit]:
        context.append(
            {
                "resource": item.get("resource"),
                "read_endpoint": item.get("read_endpoint"),
                "write_endpoint": item.get("write_endpoint"),
                "read_only_candidates": (item.get("read_only_candidates") or [])[:12],
                "mass_assignment_candidates": (item.get("mass_assignment_candidates") or [])[:12],
                "excessive_data_candidates": (item.get("excessive_data_candidates") or [])[:12],
                "confidence": item.get("confidence"),
            }
        )
    return context


def top_api_reasoning_context(
    *,
    api_dependency_graph: dict[str, Any],
    api_sequences: list[dict[str, Any]],
    handler_hypotheses: list[dict[str, Any]],
    security_invariants: list[dict[str, Any]],
    safe_manual_test_plans: list[dict[str, Any]],
    oracle_templates: list[dict[str, Any]],
    limit: int = 10,
) -> dict[str, Any]:
    edges = api_dependency_graph.get("edges") if isinstance(api_dependency_graph, dict) else []
    return {
        "dependency_edges": [
            {
                "from": item.get("from"),
                "to": item.get("to"),
                "dependency_type": item.get("dependency_type"),
                "field": item.get("field"),
                "confidence": item.get("confidence"),
            }
            for item in (edges or [])[:limit]
            if isinstance(item, dict)
        ],
        "sequences": [
            {
                "sequence_id": item.get("sequence_id"),
                "actor": item.get("actor"),
                "state": item.get("state"),
                "step_count": len(item.get("steps") or []),
                "confidence": item.get("confidence"),
            }
            for item in api_sequences[:limit]
        ],
        "handler_hypotheses": [
            {
                "endpoint_id": item.get("endpoint_id"),
                "missing_check_candidates": item.get("missing_check_candidates", [])[:5],
                "confidence": item.get("confidence"),
            }
            for item in handler_hypotheses[:limit]
        ],
        "security_invariants": [
            {
                "endpoint_id": item.get("endpoint_id"),
                "type": item.get("type"),
                "statement": item.get("statement"),
                "candidate_vulnerability": item.get("candidate_vulnerability"),
                "confidence": item.get("confidence"),
            }
            for item in security_invariants[:limit]
        ],
        "manual_test_plans": [
            {
                "test_id": item.get("test_id"),
                "endpoint_id": item.get("endpoint_id"),
                "name": item.get("name"),
                "expected_secure_result": item.get("expected_secure_result"),
                "vulnerable_if": item.get("vulnerable_if"),
                "oracle": item.get("oracle"),
            }
            for item in safe_manual_test_plans[:limit]
        ],
        "oracle_templates": [
            {
                "oracle_template_id": item.get("oracle_template_id"),
                "test_id": item.get("test_id"),
                "oracle_type": item.get("oracle_type"),
                "required_manual_fields": item.get("required_manual_fields", [])[:8],
            }
            for item in oracle_templates[:limit]
        ],
    }


def dedupe_packs_by_id(packs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for pack in packs:
        pack_id = str(pack.get("pack_id") or "")
        if not pack_id or pack_id in seen:
            continue
        seen.add(pack_id)
        output.append(pack)
    return output


def run_llm_triage_artifacts(
    cluster_evidence_packs: list[dict[str, Any]],
    *,
    config: ScopeConfig,
    output_dir: Path,
    driver_name: str,
    limit: int,
    allow_external_llm: bool,
) -> dict[str, Any]:
    output_path = output_dir / "llm-triage-results.jsonl"
    summary_path = output_dir / "llm-triage-summary.json"
    selected = cluster_evidence_packs if limit <= 0 else cluster_evidence_packs[:limit]
    audit_path = llm_audit_path(config, driver_name=driver_name)
    audit_before = load_jsonl_records(audit_path) if audit_path else []
    results: list[dict[str, Any]] = []
    if not selected:
        summary = {
            "enabled": True,
            "status": "empty",
            "driver": config.llm.primary_provider if driver_name == "auto" else driver_name,
            "input_count": len(cluster_evidence_packs),
            "submitted_count": 0,
            "succeeded": 0,
            "failed": 0,
            "schema_invalid": 0,
            "not_submitted": 0,
            "allow_external_llm": allow_external_llm,
            "llm_calls_requested": 0,
            "external_call_records": 0,
            "cache_hits_estimated": 0,
            "usage": empty_usage_summary(),
            "reason": "no_llm_triage_input_packs",
        }
        write_jsonl(output_path, results)
        write_json(summary_path, summary)
        return {
            "summary": summary,
            "artifacts": {
                "summary": str(summary_path),
                "results": str(output_path),
            },
        }

    for pack in selected:
        try:
            result = run_cluster_triage(
                pack,
                config=config,
                llm_config=config.llm,
                driver_name=driver_name,
                allow_external_llm=allow_external_llm,
            ).to_dict()
        except Exception as exc:
            result = {
                "stage": "cluster_triage",
                "llm_required": config.llm.required,
                "fail_closed": config.llm.fail_closed,
                "driver": config.llm.primary_provider if driver_name == "auto" else driver_name,
                "llm_status": "failed",
                "input_count": 1,
                "submitted_count": 0,
                "output": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
        result["pack_id"] = pack.get("pack_id")
        result["cluster_id"] = pack.get("cluster_id")
        results.append(result)

    status_counts: dict[str, int] = {}
    for result in results:
        status = str(result.get("llm_status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    failed = status_counts.get("failed", 0) + status_counts.get("schema_invalid", 0)
    audit_after = load_jsonl_records(audit_path) if audit_path else []
    new_audit = audit_after[len(audit_before) :]
    usage = usage_summary(new_audit)
    unique_jobs = {
        str(item.get("job_id") or "")
        for item in new_audit
        if isinstance(item, dict) and item.get("job_id")
    }
    summary_status = "succeeded" if failed == 0 else "partial_failed"
    if failed == len(results):
        summary_status = "failed"
    summary = {
        "enabled": True,
        "status": summary_status,
        "driver": config.llm.primary_provider if driver_name == "auto" else driver_name,
        "input_count": len(cluster_evidence_packs),
        "submitted_count": len(selected),
        "limit": max(0, limit),
        "succeeded": status_counts.get("succeeded", 0),
        "failed": status_counts.get("failed", 0),
        "schema_invalid": status_counts.get("schema_invalid", 0),
        "not_submitted": status_counts.get("not_submitted", 0),
        "status_counts": dict(sorted(status_counts.items())),
        "allow_external_llm": allow_external_llm,
        "llm_calls_requested": len(selected),
        "external_call_records": len(new_audit),
        "external_jobs_started": len(unique_jobs),
        "cache_hits_estimated": max(0, len(selected) - len(unique_jobs)),
        "audit_path": str(audit_path) if audit_path else "",
        "usage": usage,
    }
    write_jsonl(output_path, results)
    write_json(summary_path, summary)
    return {
        "summary": summary,
        "artifacts": {
            "summary": str(summary_path),
            "results": str(output_path),
        },
    }


def llm_audit_path(config: ScopeConfig, *, driver_name: str) -> Path | None:
    selected = config.llm.primary_provider if driver_name == "auto" else driver_name
    driver = (config.llm.drivers or {}).get(selected)
    if not driver or not driver.output_dir:
        return None
    return Path(driver.output_dir) / "audit.jsonl"


def usage_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    usage_records = [
        item.get("usage")
        for item in records
        if isinstance(item, dict) and isinstance(item.get("usage"), dict)
    ]
    if not usage_records:
        return empty_usage_summary()
    totals: dict[str, int] = {}
    for usage in usage_records:
        for key, value in usage.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                totals[key] = totals.get(key, 0) + value
    return {
        "available": bool(totals),
        "record_count": len(usage_records),
        "totals": dict(sorted(totals.items())),
        "estimated_cost_usd": None,
    }


def empty_usage_summary() -> dict[str, Any]:
    return {
        "available": False,
        "record_count": 0,
        "totals": {},
        "estimated_cost_usd": None,
    }


def write_dashboard_artifacts(
    output_dir: Path,
    *,
    payload: dict[str, Any],
    config: ScopeConfig,
) -> dict[str, str]:
    dashboard_json = output_dir / "dashboard.json"
    dashboard_html = output_dir / "dashboard.html"
    verification = load_json_file(output_dir / "verification-summary.json")
    review_summary = load_json_file(output_dir / "review-summary.json")
    technology_inferences = load_jsonl_records(output_dir / "technology-inference.jsonl")
    api_semantic_map = load_jsonl_records(output_dir / "api-semantic-map.jsonl")
    api_endpoint_models = load_jsonl_records(output_dir / "api-endpoints.jsonl")
    api_artifact_index = load_json_file(output_dir / "api-artifact-index.json")
    ui_field_usage = load_jsonl_records(output_dir / "ui-field-usage.jsonl")
    request_schemas = load_jsonl_records(output_dir / "request-schemas.jsonl")
    response_schemas = load_jsonl_records(output_dir / "response-schemas.jsonl")
    schema_diffs = load_jsonl_records(output_dir / "schema-diff.jsonl")
    api_dependency_graph = load_json_file(output_dir / "api-dependency-graph.json")
    api_sequences = load_jsonl_records(output_dir / "api-sequences.jsonl")
    state_transitions = load_jsonl_records(output_dir / "state-transitions.jsonl")
    handler_hypotheses = load_jsonl_records(output_dir / "handler-hypotheses.jsonl")
    security_invariants = load_jsonl_records(output_dir / "security-invariants.jsonl")
    manual_test_plans = load_jsonl_records(output_dir / "manual-test-plans.jsonl")
    oracle_templates = load_jsonl_records(output_dir / "oracle-templates.jsonl")
    llm_agent_outputs = load_jsonl_records(output_dir / "llm-agent-outputs.jsonl")
    data = {
        "program": config.program_name,
        "profile": payload.get("profile"),
        "output": str(output_dir),
        "counts": {
            "assets": payload.get("assets", 0),
            "services": payload.get("services", 0),
            "endpoints": payload.get("endpoints", 0),
            "api_docs": payload.get("api_docs", 0),
            "graphql_endpoints": payload.get("graphql_endpoints", 0),
            "source_maps": payload.get("source_maps", 0),
            "declared_endpoints": payload.get("declared_endpoints", 0),
            "technology_inferences": payload.get(
                "technology_inferences",
                len(technology_inferences),
            ),
            "api_semantics": payload.get("api_semantics", len(api_semantic_map)),
            "traffic_records": payload.get("traffic_records", 0),
            "request_schemas": payload.get("request_schemas", len(request_schemas)),
            "response_schemas": payload.get("response_schemas", len(response_schemas)),
            "api_endpoint_models": payload.get("api_endpoint_models", len(api_endpoint_models)),
            "ui_field_usage": payload.get("ui_field_usage", len(ui_field_usage)),
            "schema_diffs": payload.get("schema_diffs", len(schema_diffs)),
            "dependency_edges": payload.get(
                "dependency_edges",
                len(api_dependency_graph.get("edges") or []),
            ),
            "api_sequences": payload.get("api_sequences", len(api_sequences)),
            "state_transitions": payload.get("state_transitions", len(state_transitions)),
            "handler_hypotheses": payload.get("handler_hypotheses", len(handler_hypotheses)),
            "security_invariants": payload.get("security_invariants", len(security_invariants)),
            "manual_test_plans": payload.get("safe_manual_test_plans", len(manual_test_plans)),
            "oracle_templates": payload.get("oracle_templates", len(oracle_templates)),
            "llm_agent_outputs": payload.get("llm_agent_outputs", len(llm_agent_outputs)),
            "raw_candidates": payload.get("candidates", 0),
            "reviewable_candidates": payload.get("reviewable_candidates", 0),
            "filtered_candidates": payload.get("filtered_candidates", 0),
            "clusters": payload.get("clusters", 0),
        },
        "verification": verification,
        "filter_reason_counts": verification.get("filter_reason_counts") or {},
        "filter_category_counts": verification.get("filter_category_counts") or {},
        "tool_failures": [
            item
            for item in payload.get("results") or []
            if item.get("error") and not item.get("skipped")
        ],
        "auth_crawl": auth_summary(config),
        "technology_context": top_technology_context(technology_inferences),
        "api_semantic_summary": summarize_semantic_map(api_semantic_map),
        "api_semantic_context": top_api_semantic_context(api_semantic_map),
        "api_artifact_index_summary": api_artifact_index.get("counts", {}),
        "api_reasoning_context": top_api_reasoning_context(
            api_dependency_graph=api_dependency_graph,
            api_sequences=api_sequences,
            handler_hypotheses=handler_hypotheses,
            security_invariants=security_invariants,
            safe_manual_test_plans=manual_test_plans,
            oracle_templates=oracle_templates,
        ),
        "llm_triage": payload.get("llm_triage") or {"enabled": False, "status": "not_run"},
        "review_status": review_summary.get("status"),
        "artifacts": {
            "report": "report.md",
            "review": "review.md",
            "verification_debug": "verification-debug.md",
            "summary": "summary.json",
            "review_queue": "review-queue.json",
            "llm_triage_queue": "llm-triage-queue.json",
            "llm_triage_summary": "llm-triage-summary.json",
            "endpoints": "endpoints.jsonl",
            "api_docs": "api-docs.jsonl",
            "technology_inference": "technology-inference.jsonl",
            "api_semantic_map": "api-semantic-map.jsonl",
            "traffic": "traffic.jsonl",
            "request_schemas": "request-schemas.jsonl",
            "response_schemas": "response-schemas.jsonl",
            "api_endpoints": "api-endpoints.jsonl",
            "api_artifact_index": "api-artifact-index.json",
            "ui_field_usage": "ui-field-usage.jsonl",
            "parameter_classification": "parameter-classification.jsonl",
            "schema_diff": "schema-diff.jsonl",
            "api_dependency_graph": "api-dependency-graph.json",
            "api_sequences": "api-sequences.jsonl",
            "state_transitions": "state-transitions.jsonl",
            "handler_hypotheses": "handler-hypotheses.jsonl",
            "security_invariants": "security-invariants.jsonl",
            "manual_test_plans": "manual-test-plans.jsonl",
            "oracle_templates": "oracle-templates.jsonl",
            "llm_agent_outputs": "llm-agent-outputs.jsonl",
        },
    }
    write_json(dashboard_json, data)
    dashboard_html.write_text(render_dashboard_html(data), encoding="utf-8")
    return {"dashboard_json": str(dashboard_json), "dashboard_html": str(dashboard_html)}


def load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def render_dashboard_html(data: dict[str, Any]) -> str:
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    filter_counts = (
        data.get("filter_reason_counts")
        if isinstance(data.get("filter_reason_counts"), dict)
        else {}
    )
    category_counts = (
        data.get("filter_category_counts")
        if isinstance(data.get("filter_category_counts"), dict)
        else {}
    )
    tool_failures = data.get("tool_failures") if isinstance(data.get("tool_failures"), list) else []
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    llm = data.get("llm_triage") if isinstance(data.get("llm_triage"), dict) else {}
    auth = data.get("auth_crawl") if isinstance(data.get("auth_crawl"), dict) else {}
    api_semantic_context = (
        data.get("api_semantic_context")
        if isinstance(data.get("api_semantic_context"), list)
        else []
    )
    api_semantic_summary = (
        data.get("api_semantic_summary")
        if isinstance(data.get("api_semantic_summary"), dict)
        else {}
    )

    def failure_row(item: dict[str, Any]) -> str:
        plan = item.get("plan") if isinstance(item.get("plan"), dict) else {}
        tool_name = plan.get("name") or item.get("name") or "tool"
        return (
            "<tr>"
            f"<td>{escape(str(tool_name))}</td>"
            f"<td>{escape(str(item.get('error') or 'error'))}</td>"
            "</tr>"
        )

    def artifact_row(label: object, path: object) -> str:
        safe_label = escape(str(label))
        safe_path = escape(str(path))
        return f'<tr><td>{safe_label}</td><td><a href="{safe_path}">{safe_path}</a></td></tr>'

    count_cards = "\n".join(
        f"<section><strong>{escape(str(key))}</strong><span>{escape(str(value))}</span></section>"
        for key, value in counts.items()
    )
    filter_rows = "\n".join(
        f"<tr><td>{escape(str(key))}</td><td>{escape(str(value))}</td></tr>"
        for key, value in sorted(filter_counts.items(), key=lambda item: str(item[0]))
    )
    category_rows = "\n".join(
        f"<tr><td>{escape(str(key))}</td><td>{escape(str(value))}</td></tr>"
        for key, value in sorted(category_counts.items(), key=lambda item: str(item[0]))
    )
    failure_rows = "\n".join(
        failure_row(item) for item in tool_failures[:20] if isinstance(item, dict)
    )
    artifact_rows = "\n".join(artifact_row(label, path) for label, path in artifacts.items())
    api_semantic_rows = "\n".join(
        "<tr>"
        f"<td>{escape(str(item.get('method') or 'GET'))}</td>"
        f"<td>{escape(str(item.get('url') or ''))}</td>"
        f"<td>{escape(str(item.get('resource') or 'unknown'))}</td>"
        f"<td>{escape(str(item.get('action') or 'unknown'))}</td>"
        f"<td>{escape(str(item.get('auth_guess') or 'unknown'))}</td>"
        f"<td>{escape(str(item.get('risk_weight') or 0))}</td>"
        "</tr>"
        for item in api_semantic_context[:20]
        if isinstance(item, dict)
    )
    api_summary_text = escape(json.dumps(api_semantic_summary, ensure_ascii=False, indent=2))
    usage = llm.get("usage") if isinstance(llm.get("usage"), dict) else {}
    empty_api_semantic_row = (
        "<tr><td>none</td><td>none</td><td>none</td><td>none</td><td>none</td><td>0</td></tr>"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DONZO Dashboard</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #1f2933; background: #f5f7fa; }}
    header {{ padding: 24px 28px; background: #12343b; color: white; }}
    main {{ padding: 24px 28px; max-width: 1180px; margin: 0 auto; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }}
    section, .panel {{
      background: white;
      border: 1px solid #d9e2ec;
      border-radius: 8px;
      padding: 14px;
    }}
    section span {{ display: block; margin-top: 8px; font-size: 24px; font-weight: 700; }}
    .panels {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-top: 18px;
    }}
    input {{
      width: 100%;
      box-sizing: border-box;
      margin: 18px 0;
      padding: 10px 12px;
      border: 1px solid #bcccdc;
      border-radius: 6px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
      padding: 8px 6px;
      border-bottom: 1px solid #eef2f6;
      text-align: left;
      vertical-align: top;
    }}
    th {{ cursor: pointer; color: #334e68; font-size: 13px; }}
    a {{ display: inline-block; margin: 0 10px 10px 0; color: #0b5cad; }}
    code {{ background: #eef2f6; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
  <header>
    <h1>DONZO Dashboard</h1>
    <div>{escape(str(data.get("program") or ""))} / {escape(str(data.get("profile") or ""))}</div>
  </header>
  <main>
    <div class="grid">{count_cards}</div>
    <input id="dashboard-search" type="search" placeholder="Filter dashboard rows">
    <div class="panels">
      <div class="panel">
        <h2>Verification Filters</h2>
        <table class="searchable sortable">
          <thead><tr><th>Reason</th><th>Count</th></tr></thead>
          <tbody>{filter_rows or "<tr><td>none</td><td>0</td></tr>"}</tbody>
        </table>
      </div>
      <div class="panel">
        <h2>Filter Categories</h2>
        <table class="searchable sortable">
          <thead><tr><th>Category</th><th>Count</th></tr></thead>
          <tbody>{category_rows or "<tr><td>none</td><td>0</td></tr>"}</tbody>
        </table>
      </div>
      <div class="panel">
        <h2>LLM Triage</h2>
        <p>Status: <code>{escape(str(llm.get("status") or "not_run"))}</code></p>
        <p>Submitted: <code>{escape(str(llm.get("submitted_count") or 0))}</code></p>
        <p>Calls requested: <code>{escape(str(llm.get("llm_calls_requested") or 0))}</code></p>
        <p>External jobs: <code>{escape(str(llm.get("external_jobs_started") or 0))}</code></p>
        <p>
          Cache hits estimated:
          <code>{escape(str(llm.get("cache_hits_estimated") or 0))}</code>
        </p>
        <p>Usage available: <code>{escape(str(usage.get("available") or False))}</code></p>
      </div>
      <div class="panel">
        <h2>Authenticated Crawl</h2>
        <p>Enabled: <code>{escape(str(auth.get("enabled") or False))}</code></p>
        <p>Headers present: <code>{escape(str(auth.get("header_count") or 0))}</code></p>
      </div>
      <div class="panel">
        <h2>API Semantic Summary</h2>
        <pre><code>{api_summary_text}</code></pre>
      </div>
      <div class="panel">
        <h2>Tool Failures</h2>
        <table class="searchable sortable">
          <thead><tr><th>Tool</th><th>Error</th></tr></thead>
          <tbody>{failure_rows or "<tr><td>none</td><td>0</td></tr>"}</tbody>
        </table>
      </div>
    </div>
    <div class="panel" style="margin-top:18px">
      <h2>API Semantic Map</h2>
      <table class="searchable sortable">
        <thead>
          <tr>
            <th>Method</th><th>URL</th><th>Resource</th>
            <th>Action</th><th>Auth</th><th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {api_semantic_rows or empty_api_semantic_row}
        </tbody>
      </table>
    </div>
    <div class="panel" style="margin-top:18px">
      <h2>Artifacts</h2>
      <table class="searchable sortable">
        <thead><tr><th>Name</th><th>Path</th></tr></thead>
        <tbody>{artifact_rows}</tbody>
      </table>
    </div>
  </main>
  <script>
    const search = document.getElementById('dashboard-search');
    search.addEventListener('input', () => {{
      const query = search.value.toLowerCase();
      document.querySelectorAll('table.searchable tbody tr').forEach((row) => {{
        row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
      }});
    }});
    document.querySelectorAll('table.sortable th').forEach((header) => {{
      header.addEventListener('click', () => {{
        const table = header.closest('table');
        const index = Array.from(header.parentElement.children).indexOf(header);
        const rows = Array.from(table.querySelectorAll('tbody tr'));
        const ascending = header.dataset.sort !== 'asc';
        rows.sort((a, b) => {{
          const av = a.children[index].textContent.trim();
          const bv = b.children[index].textContent.trim();
          const an = Number(av);
          const bn = Number(bv);
          const result = Number.isFinite(an) && Number.isFinite(bn)
            ? an - bn
            : av.localeCompare(bv);
          return ascending ? result : -result;
        }});
        header.dataset.sort = ascending ? 'asc' : 'desc';
        rows.forEach((row) => table.querySelector('tbody').appendChild(row));
      }});
    }});
  </script>
</body>
</html>
"""


def build_run_diff(
    previous_dir: Path,
    current_dir: Path,
    *,
    output_path: Path | None = None,
) -> dict[str, Any]:
    previous_endpoints = load_jsonl_records(previous_dir / "endpoints.jsonl")
    current_endpoints = load_jsonl_records(current_dir / "endpoints.jsonl")
    previous_candidates = load_jsonl_records(previous_dir / "candidates-verified.jsonl")
    current_candidates = load_jsonl_records(current_dir / "candidates-verified.jsonl")
    previous_findings = load_jsonl_records(previous_dir / "findings.jsonl")
    current_findings = load_jsonl_records(current_dir / "findings.jsonl")

    new_endpoints = new_records(previous_endpoints, current_endpoints, key_fields=("url",))
    new_candidates = new_records(
        previous_candidates,
        current_candidates,
        key_fields=("finding_id", "candidate_id", "target", "candidate_type"),
    )
    new_findings = new_records(
        previous_findings,
        current_findings,
        key_fields=("finding_id", "target", "candidate_type", "title"),
    )
    payload = {
        "summary": {
            "previous": str(previous_dir),
            "current": str(current_dir),
            "new_endpoints": len(new_endpoints),
            "new_candidates": len(new_candidates),
            "new_findings": len(new_findings),
        },
        "new_endpoints": new_endpoints,
        "new_candidates": new_candidates,
        "new_findings": new_findings,
    }
    target_path = output_path or (current_dir / "run-diff.json")
    write_json(target_path, payload)
    markdown_path = target_path.with_suffix(".md")
    markdown_path.write_text(render_run_diff_markdown(payload), encoding="utf-8")
    return payload


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            records.append(data)
    return records


def new_records(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
    *,
    key_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    previous_keys = {record_identity(record, key_fields=key_fields) for record in previous}
    return [
        record
        for record in current
        if record_identity(record, key_fields=key_fields) not in previous_keys
    ]


def record_identity(record: dict[str, Any], *, key_fields: tuple[str, ...]) -> str:
    parts: list[str] = []
    for field in key_fields:
        value = str(record.get(field) or "")
        if value:
            parts.append(f"{field}={value}")
    if parts:
        return "|".join(parts)
    return stable_record_json(record)


def stable_record_json(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def render_run_diff_markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# DONZO Run Diff",
        "",
        f"- Previous: {summary.get('previous', '')}",
        f"- Current: {summary.get('current', '')}",
        f"- New Endpoints: {summary.get('new_endpoints', 0)}",
        f"- New Candidates: {summary.get('new_candidates', 0)}",
        f"- New Findings: {summary.get('new_findings', 0)}",
        "",
        "## New Endpoints",
        "",
    ]
    for endpoint in payload.get("new_endpoints") or []:
        if isinstance(endpoint, dict):
            lines.append(f"- {endpoint.get('method', 'GET')} {endpoint.get('url', '')}")
    if not payload.get("new_endpoints"):
        lines.append("- None")
    lines.extend(["", "## New Candidates", ""])
    for candidate in payload.get("new_candidates") or []:
        if isinstance(candidate, dict):
            lines.append(
                f"- {candidate.get('candidate_type', 'candidate')} {candidate.get('target', '')}"
            )
    if not payload.get("new_candidates"):
        lines.append("- None")
    lines.extend(["", "## New Findings", ""])
    for finding in payload.get("new_findings") or []:
        if isinstance(finding, dict):
            lines.append(f"- {finding.get('title') or finding.get('target') or 'finding'}")
    if not payload.get("new_findings"):
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def emit_progress(callback: ProgressCallback | None, event: dict[str, Any]) -> None:
    if callback is not None:
        callback(event)


def emit_pipeline_step_started(callback: ProgressCallback | None, name: str) -> None:
    emit_progress(callback, {"event": "pipeline_step_started", "name": name})


def emit_pipeline_step_finished(callback: ProgressCallback | None, name: str) -> None:
    emit_progress(callback, {"event": "pipeline_step_finished", "name": name})


def write_phase_state(
    output_dir: Path,
    state: dict[str, Any],
    *,
    phase: str,
    counters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = transition_run_state(
        state,
        status="running",
        phase=phase,
        counters=counters,
    )
    write_run_state(output_dir, state)
    return state


def build_pipeline_progress_steps(tool_preflight: dict[str, Any]) -> list[dict[str, Any]]:
    first_status = "done" if not tool_preflight.get("missing") else "blocked"
    first_percent = 100 if first_status in {"done", "blocked"} else 0
    steps: list[dict[str, Any]] = []
    for index, name in enumerate(PIPELINE_PROGRESS_STEPS):
        if index == 0:
            steps.append({"name": name, "status": first_status, "percent": first_percent})
        else:
            steps.append({"name": name, "status": "pending", "percent": 0})
    return steps


def discover_js_static_endpoints(
    js_files: list[dict[str, Any]],
    *,
    config: ScopeConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    discovered: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    max_fetches = js_network_fetch_limit(config)
    interval = 0.0
    if config.rate_limit.max_requests_per_second > 0:
        interval = 1.0 / config.rate_limit.max_requests_per_second
    last_probe = 0.0
    fetched = 0

    for endpoint in js_files:
        if fetched >= max_fetches:
            break
        target = str(endpoint.get("url") or "")
        if not target:
            continue
        decision = config.scope.decide(target)
        if not decision.allowed:
            removed.append({"record": target, "reason": "; ".join(decision.reasons)})
            continue
        if interval:
            elapsed = time.monotonic() - last_probe
            if elapsed < interval:
                time.sleep(interval - elapsed)
        probe = probe_url(target, config=config, method="GET")
        last_probe = time.monotonic()
        fetched += 1
        if not probe.status_code or not (200 <= probe.status_code < 300):
            removed.append(
                {
                    "record": target,
                    "reason": "js_fetch_failed",
                    "status_code": probe.status_code,
                    "error_signature": probe.error_signature,
                }
            )
            continue
        if not config.scope.decide(probe.final_url).allowed:
            removed.append({"record": target, "reason": "redirect_final_url_out_of_scope"})
            continue
        endpoints, js_removed = extract_endpoints_from_js_text(
            probe.body_text,
            base_url=probe.final_url or target,
            config=config,
            source="js_network_static",
        )
        discovered.extend(endpoints)
        removed.extend(js_removed)
    return dedupe_records(discovered), removed


def discover_declared_site_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    config: ScopeConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    discovered: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    interval = 0.0
    if config.rate_limit.max_requests_per_second > 0:
        interval = 1.0 / config.rate_limit.max_requests_per_second
    last_probe = 0.0
    sitemap_fetches = 0
    max_sitemap_fetches = declared_sitemap_probe_limit(config)

    for base_url in endpoint_base_urls(endpoints):
        robots_url = openapi_url(base_url, "/robots.txt")
        if interval:
            elapsed = time.monotonic() - last_probe
            if elapsed < interval:
                time.sleep(interval - elapsed)
        robots_probe = probe_url(robots_url, config=config, method="GET")
        last_probe = time.monotonic()
        sitemap_urls = [openapi_url(base_url, "/sitemap.xml")]
        if robots_probe.status_code and 200 <= robots_probe.status_code < 300:
            robots_endpoints, robots_sitemaps, robots_removed = endpoints_from_robots_text(
                robots_probe.body_text,
                base_url=robots_probe.final_url or robots_url,
                config=config,
                source="robots",
            )
            discovered.extend(robots_endpoints)
            removed.extend(robots_removed)
            sitemap_urls.extend(robots_sitemaps)
        elif robots_probe.status_code not in {404, 410}:
            removed.append(
                {
                    "record": robots_url,
                    "reason": "robots_fetch_failed",
                    "status_code": robots_probe.status_code,
                    "error_signature": robots_probe.error_signature,
                }
            )

        for sitemap_url in dedupe_string_values(sitemap_urls):
            if sitemap_fetches >= max_sitemap_fetches:
                break
            if not config.scope.decide(sitemap_url).allowed:
                continue
            if interval:
                elapsed = time.monotonic() - last_probe
                if elapsed < interval:
                    time.sleep(interval - elapsed)
            sitemap_probe = probe_url(sitemap_url, config=config, method="GET")
            last_probe = time.monotonic()
            sitemap_fetches += 1
            if not sitemap_probe.status_code or not (200 <= sitemap_probe.status_code < 300):
                continue
            sitemap_endpoints, sitemap_removed = endpoints_from_sitemap_text(
                sitemap_probe.body_text,
                config=config,
                source="sitemap",
            )
            discovered.extend(sitemap_endpoints)
            removed.extend(sitemap_removed)
    return dedupe_records(discovered), removed


def declared_sitemap_probe_limit(config: ScopeConfig) -> int:
    origin_count = max(1, len(scope_seed_urls(config)))
    return min(12, origin_count * 3)


def dedupe_string_values(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            output.append(normalized)
            seen.add(normalized)
    return output


def discover_openapi_schema_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    config: ScopeConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    discovered_endpoints: list[dict[str, Any]] = []
    discovered_docs: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    max_success_per_origin = max(0, config.verification.api_docs.max_schema_fetches)
    if max_success_per_origin == 0:
        return [], [], []
    interval = 0.0
    if config.rate_limit.max_requests_per_second > 0:
        interval = 1.0 / config.rate_limit.max_requests_per_second
    last_probe = 0.0
    max_total_probes = openapi_schema_probe_limit(config)
    probe_count = 0

    for base_url in endpoint_base_urls(endpoints):
        success_count = 0
        for path in OPENAPI_SCHEMA_PATHS:
            if probe_count >= max_total_probes:
                return (
                    dedupe_records(discovered_endpoints),
                    dedupe_records(discovered_docs),
                    removed,
                )
            if success_count >= max_success_per_origin:
                break
            target = openapi_url(base_url, path)
            decision = config.scope.decide(target)
            if not decision.allowed:
                removed.append({"record": target, "reason": "; ".join(decision.reasons)})
                continue
            if interval:
                elapsed = time.monotonic() - last_probe
                if elapsed < interval:
                    time.sleep(interval - elapsed)
            probe = probe_url(target, config=config, method="GET")
            last_probe = time.monotonic()
            probe_count += 1
            if not probe.status_code or not (200 <= probe.status_code < 300):
                removed.append(
                    {
                        "record": target,
                        "reason": "openapi_schema_not_found",
                        "status_code": probe.status_code,
                        "error_signature": probe.error_signature,
                    }
                )
                continue
            if not config.scope.decide(probe.final_url).allowed:
                removed.append({"record": target, "reason": "redirect_final_url_out_of_scope"})
                continue
            document = parse_openapi_document_text(probe.body_text, probe.content_type)
            if document is None:
                removed.append(
                    {
                        "record": target,
                        "reason": "openapi_schema_parse_failed",
                        "status_code": probe.status_code,
                        "content_type": probe.content_type,
                    }
                )
                continue
            doc_records, doc_removed = normalize_endpoint_records(
                [
                    {
                        "url": probe.final_url,
                        "method": "GET",
                        "status_code": probe.status_code,
                        "content_type": probe.content_type,
                    }
                ],
                config=config,
                source="openapi_network_schema",
            )
            discovered_docs.extend(doc_records)
            removed.extend(doc_removed)
            schema_endpoints, schema_removed = endpoints_from_openapi_document(
                document,
                base_url=base_url,
                config=config,
                source="openapi_network_schema",
            )
            discovered_endpoints.extend(schema_endpoints)
            removed.extend(schema_removed)
            success_count += 1
    return dedupe_records(discovered_endpoints), dedupe_records(discovered_docs), removed


def confirmed_api_doc_endpoints(
    api_docs: list[dict[str, Any]],
    verified_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    verified_targets = {
        str(item.get("target") or "")
        for item in verified_candidates
        if str(item.get("candidate_type") or "").upper() in {"EXPOSED_API_DOCS", "PUBLIC_SWAGGER"}
        and str(item.get("verification_status") or "") == "verified"
    }
    confirmed: list[dict[str, Any]] = []
    for endpoint in api_docs:
        url = str(endpoint.get("url") or "")
        sources = {str(item) for item in endpoint.get("source") or []}
        if url in verified_targets or "openapi_network_schema" in sources:
            confirmed.append(endpoint)
    return dedupe_records(confirmed)


def declared_site_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for endpoint in endpoints:
        sources = {str(item) for item in endpoint.get("source") or []}
        if sources & {"robots", "sitemap"}:
            output.append(endpoint)
    return dedupe_records(output)


def build_fast_recon_plans(
    *,
    config: ScopeConfig,
    output_dir: Path,
    dry_run: bool = True,
) -> list[CommandPlan]:
    return build_recon_command_plans(
        config=config,
        output_dir=output_dir,
        profile="fast",
        dry_run=dry_run,
    )


def build_recon_command_plans(
    *,
    config: ScopeConfig,
    output_dir: Path,
    profile: str,
    dry_run: bool = True,
) -> list[CommandPlan]:
    raw_dir = output_dir / "raw"
    derived_dir = output_dir / "derived"
    roots = root_domains(config)
    domain_arg = ",".join(roots)
    root_file = derived_dir / "root_domains.txt"
    candidate_assets_file = derived_dir / "candidate_assets.txt"
    http_probe_assets_file = derived_dir / "http_probe_assets.txt"
    archive_urls_file = derived_dir / "archive_urls.txt"
    live_urls_file = derived_dir / "live_urls.txt"
    rate = cli_positive_int(config.rate_limit.max_requests_per_second)
    concurrency = cli_positive_int(config.rate_limit.max_concurrency)
    timeout = cli_positive_int(config.rate_limit.timeout_seconds)
    plans = [
        build_command_plan(
            config=config,
            name="subfinder",
            argv=[
                tool_binary("subfinder"),
                "-d",
                domain_arg,
                "-silent",
                "-rl",
                rate,
                *tool_limit_args("-timeout", timeout, profile=profile),
            ],
            output_path=raw_dir / "subfinder.txt",
            targets=roots,
            required_policy_flag="passive_recon",
            dry_run=dry_run,
        ),
    ]
    if profile == "deep" and config.policy.is_enabled("passive_recon"):
        plans.extend(
            [
                build_command_plan(
                    config=config,
                    name="alterx",
                    argv=[
                        tool_binary("alterx"),
                        "-l",
                        "stdin",
                        "-silent",
                    ],
                    output_path=raw_dir / "alterx.txt",
                    targets=roots,
                    required_policy_flag="passive_recon",
                    stdin_path=raw_dir / "subfinder.txt",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="amass",
                    argv=[
                        tool_binary("amass"),
                        "enum",
                        "-passive",
                        *domain_flag_args(roots),
                    ],
                    output_path=raw_dir / "amass.txt",
                    targets=roots,
                    required_policy_flag="passive_recon",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="bbot",
                    argv=[
                        tool_binary("bbot"),
                        "-t",
                        *roots,
                        "-w",
                        *roots,
                        "--strict-scope",
                        "-p",
                        "subdomain-enum",
                        "-rf",
                        "passive",
                        "-ef",
                        "active",
                        "aggressive",
                        "deadly",
                        "portscan",
                        "web-thorough",
                        "web-paramminer",
                        "-om",
                        "subdomains",
                        "--brief",
                        "--silent",
                        "--no-deps",
                        "-y",
                    ],
                    output_path=raw_dir / "bbot.txt",
                    targets=roots,
                    required_policy_flag="passive_recon",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="uncover",
                    argv=[
                        tool_binary("uncover"),
                        *uncover_engine_args(),
                        *repeated_flag_args("-q", roots),
                        "-f",
                        "host",
                        "-silent",
                        "-l",
                        "100",
                        "-rl",
                        rate,
                        *tool_limit_args("-timeout", timeout, profile=profile),
                    ],
                    output_path=raw_dir / "uncover.txt",
                    targets=roots,
                    required_policy_flag="passive_recon",
                    dry_run=dry_run,
                ),
            ]
        )
    plans.append(
        build_command_plan(
            config=config,
            name="dnsx",
            argv=[
                tool_binary("dnsx"),
                "-l",
                str(candidate_assets_file),
                "-silent",
                "-t",
                concurrency,
                "-rl",
                rate,
                *tool_limit_args("-timeout", f"{timeout}s", profile=profile),
            ],
            output_path=raw_dir / "dnsx.txt",
            targets=roots,
            required_policy_flag="active_recon",
            dry_run=dry_run,
        )
    )
    if profile == "deep" and config.policy.is_enabled("active_recon"):
        plans.append(
            build_command_plan(
                config=config,
                name="tlsx",
                argv=[
                    tool_binary("tlsx"),
                    "-l",
                    str(candidate_assets_file),
                    "-json",
                    "-silent",
                ],
                output_path=raw_dir / "tlsx.jsonl",
                targets=roots,
                required_policy_flag="active_recon",
                dry_run=dry_run,
            )
        )
    plans.extend(
        [
            build_command_plan(
                config=config,
                name="httpx",
                argv=[
                    tool_binary("httpx"),
                    "-l",
                    str(http_probe_assets_file),
                    "-json",
                    "-silent",
                    "-title",
                    "-server",
                    "-td",
                    "-ct",
                    "-cl",
                    "-favicon",
                    "-jarm",
                    "-tls-grab",
                    "-cname",
                    "-cdn",
                    "-probe",
                    "-t",
                    concurrency,
                    "-rl",
                    rate,
                    *tool_limit_args("-timeout", timeout, profile=profile),
                ],
                output_path=raw_dir / "httpx.jsonl",
                targets=roots,
                required_policy_flag="active_recon",
                dry_run=dry_run,
            ),
        ]
    )
    if profile in {"normal", "deep"} and config.policy.is_enabled("archive_collection"):
        plans.extend(
            [
                build_command_plan(
                    config=config,
                    name="gau",
                    argv=[
                        tool_binary("gau"),
                        "--threads",
                        concurrency,
                        *tool_limit_args("--timeout", timeout, profile=profile),
                        *roots,
                    ],
                    output_path=raw_dir / "gau.txt",
                    targets=roots,
                    required_policy_flag="archive_collection",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="waybackurls",
                    argv=[tool_binary("waybackurls"), *roots],
                    output_path=raw_dir / "waybackurls.txt",
                    targets=roots,
                    required_policy_flag="archive_collection",
                    dry_run=dry_run,
                ),
            ]
        )
        if profile == "deep":
            plans.append(
                build_command_plan(
                    config=config,
                    name="waymore",
                    argv=[
                        tool_binary("waymore"),
                        "-i",
                        str(root_file),
                        "-mode",
                        "U",
                        "--stream",
                        "-p",
                        concurrency,
                        *tool_limit_args("-t", timeout, profile=profile),
                        "-lr",
                        "250",
                    ],
                    output_path=raw_dir / "waymore.txt",
                    targets=roots,
                    required_policy_flag="archive_collection",
                    dry_run=dry_run,
                )
            )
    katana_auth_args, katana_auth_redacted_args, _auth_summary = auth_tool_header_args(
        scope_seed_urls(config),
        config=config,
    )
    katana_argv = [
        tool_binary("katana"),
        "-list",
        str(live_urls_file),
        "-jsonl",
        "-silent",
        "-c",
        concurrency,
        "-p",
        "1",
        "-rl",
        rate,
        *katana_limit_args(config, timeout, profile=profile),
        "-iqp",
        "-fsu",
        "-ob",
        "-or",
        *katana_auth_args,
    ]
    katana_redacted_argv = [
        tool_binary("katana"),
        "-list",
        str(live_urls_file),
        "-jsonl",
        "-silent",
        "-c",
        concurrency,
        "-p",
        "1",
        "-rl",
        rate,
        *katana_limit_args(config, timeout, profile=profile),
        "-iqp",
        "-fsu",
        "-ob",
        "-or",
        *katana_auth_redacted_args,
    ]
    plans.append(
        build_command_plan(
            config=config,
            name="katana",
            argv=katana_argv,
            output_path=raw_dir / "katana.jsonl",
            targets=roots,
            required_policy_flag="crawling",
            dry_run=dry_run,
            redacted_argv=katana_redacted_argv if katana_auth_args else None,
        )
    )
    if profile == "deep" and config.policy.is_enabled("parameter_mining"):
        plans.extend(
            [
                build_command_plan(
                    config=config,
                    name="paramspider",
                    argv=[
                        tool_binary("paramspider"),
                        "-l",
                        str(root_file),
                        "-s",
                    ],
                    output_path=raw_dir / "paramspider.txt",
                    targets=roots,
                    required_policy_flag="parameter_mining",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="qsreplace",
                    argv=[tool_binary("qsreplace"), "DONZO_PARAM_VALUE"],
                    output_path=raw_dir / "qsreplace.txt",
                    targets=roots,
                    required_policy_flag="parameter_mining",
                    stdin_path=archive_urls_file,
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="arjun",
                    argv=[
                        tool_binary("arjun"),
                        "-i",
                        str(live_urls_file),
                        "--passive",
                        "-oT",
                        str(raw_dir / "arjun.txt"),
                        "-t",
                        concurrency,
                        "--rate-limit",
                        rate,
                        *tool_limit_args("-T", timeout, profile=profile),
                        "-q",
                    ],
                    output_path=raw_dir / "arjun.stdout",
                    targets=roots,
                    required_policy_flag="parameter_mining",
                    test_type="parameter_fuzzing",
                    dry_run=dry_run,
                ),
            ]
        )
    if profile == "deep" and config.policy.is_enabled("content_discovery"):
        plans.extend(
            [
                build_command_plan(
                    config=config,
                    name="kiterunner",
                    argv=[
                        tool_binary("kiterunner"),
                        "scan",
                        str(live_urls_file),
                        "-A",
                        "apiroutes-210228:200",
                        "-x",
                        concurrency,
                        "-j",
                        concurrency,
                        *tool_limit_args("-t", f"{timeout}s", profile=profile),
                        "-o",
                        "json",
                        "-q",
                    ],
                    output_path=raw_dir / "kiterunner.jsonl",
                    targets=roots,
                    required_policy_flag="content_discovery",
                    test_type="content_fuzzing",
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="kxss",
                    argv=[tool_binary("kxss")],
                    output_path=raw_dir / "kxss.txt",
                    targets=roots,
                    required_policy_flag="content_discovery",
                    test_type="parameter_fuzzing",
                    stdin_path=raw_dir / "qsreplace.txt",
                    dry_run=dry_run,
                ),
            ]
        )
    if profile == "deep":
        plans.extend(
            [
                build_command_plan(
                    config=config,
                    name="gitleaks",
                    argv=[
                        tool_binary("gitleaks"),
                        "detect",
                        "--no-git",
                        "--source",
                        str(derived_dir),
                        "--report-format",
                        "json",
                        "--report-path",
                        "-",
                        "--redact=100",
                        "--exit-code",
                        "0",
                        "--no-banner",
                    ],
                    output_path=raw_dir / "gitleaks.json",
                    targets=roots,
                    dry_run=dry_run,
                ),
                build_command_plan(
                    config=config,
                    name="trufflehog",
                    argv=[
                        tool_binary("trufflehog"),
                        "filesystem",
                        "--json",
                        "--no-verification",
                        "--results=unknown,unverified",
                        "--no-update",
                        "--no-color",
                        "--directory",
                        str(derived_dir),
                    ],
                    output_path=raw_dir / "trufflehog.jsonl",
                    targets=roots,
                    dry_run=dry_run,
                ),
            ]
        )
    if profile in {"normal", "deep"} and config.policy.is_enabled("port_scan"):
        plans.append(
            build_command_plan(
                config=config,
                name="naabu",
                argv=[
                    tool_binary("naabu"),
                    "-list",
                    str(raw_dir / "dnsx.txt"),
                    "-json",
                    "-silent",
                    "-top-ports",
                    "100",
                ],
                output_path=raw_dir / "naabu.jsonl",
                targets=roots,
                required_policy_flag="port_scan",
                dry_run=dry_run,
            )
        )
    if config.policy.is_enabled("nuclei_scan"):
        plans.append(
            build_command_plan(
                config=config,
                name="nuclei",
                argv=[
                    tool_binary("nuclei"),
                    "-list",
                    str(live_urls_file),
                    "-jsonl",
                    "-silent",
                    "-severity",
                    "low,medium,high,critical",
                    "-exclude-tags",
                    "dos,intrusive,destructive,bruteforce,fuzz",
                ],
                output_path=raw_dir / "nuclei.jsonl",
                targets=roots,
                required_policy_flag="nuclei_scan",
                dry_run=dry_run,
            )
        )
    return plans


def build_tool_preflight(plans: list[CommandPlan], *, profile: str) -> dict[str, Any]:
    tool_names = sorted({plan.name for plan in plans})
    statuses = check_tools(tool_names)
    status_by_name = {str(item["name"]): item for item in statuses}
    items: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    skipped_optional: list[dict[str, Any]] = []
    for plan in plans:
        status = status_by_name.get(plan.name)
        if status is None:
            status = {
                "name": plan.name,
                "available": False,
                "error": "tool_not_registered",
                "path": None,
                "version": None,
            }
        required_for_run = plan.allowed and is_required_for_profile(status, profile)
        if required_for_run:
            skip_reason = ""
        elif not plan.allowed:
            skip_reason = plan_policy_skip_reason(plan)
        else:
            skip_reason = optional_tool_skip_reason(plan.name, profile=profile)
        item = {
            **status,
            "planned": True,
            "required_for_run": required_for_run,
            "plan_allowed": plan.allowed,
            "plan_reasons": plan.reasons,
            "output_path": str(plan.output_path),
            "skip_reason": skip_reason or None,
        }
        items.append(item)
        if item["required_for_run"] and not item["available"]:
            missing.append(item)
        if not item["required_for_run"] and skip_reason:
            skipped_optional.append(item)
    return {
        "ok": not missing,
        "profile": profile,
        "checked_at": now_utc(),
        "tool_count": len(items),
        "missing_count": len(missing),
        "missing": missing,
        "skipped_optional": skipped_optional,
        "tools": items,
    }


def optional_skipped_tools(tool_preflight: dict[str, Any]) -> dict[str, str]:
    skipped: dict[str, str] = {}
    for item in tool_preflight.get("tools") or []:
        if item.get("required_for_run"):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        reason = str(item.get("skip_reason") or "")
        if reason:
            skipped[name] = reason
            continue
        if not item.get("plan_allowed"):
            skipped[name] = "policy_blocked"
            continue
        if not item.get("available"):
            skipped[name] = str(item.get("error") or "optional_tool_missing")
    return skipped


def required_tool_name_map(tool_preflight: dict[str, Any]) -> dict[str, bool]:
    return {
        str(item.get("name") or ""): bool(item.get("required_for_run"))
        for item in tool_preflight.get("tools") or []
        if item.get("name")
    }


def command_timeout_seconds(
    name: str,
    *,
    profile: str | None = None,
    config: ScopeConfig,
    required_for_run: bool,
) -> float | None:
    if name == "bbot":
        return bbot_hang_guard_seconds()
    if use_tool_default_limits(profile):
        return None
    if override := command_timeout_override_seconds(name):
        return override
    long_recon = os.environ.get("DONZO_LONG_RECON")
    if name in {"dnsx", "httpx"}:
        if long_recon:
            return max(60.0, min(300.0, config.rate_limit.timeout_seconds * 8))
        return max(30.0, min(90.0, config.rate_limit.timeout_seconds * 8))
    if name == "katana":
        if long_recon:
            return max(90.0, min(600.0, config.rate_limit.timeout_seconds * 8))
        return max(30.0, min(90.0, config.rate_limit.timeout_seconds * 6))
    if required_for_run:
        if long_recon:
            return max(90.0, min(600.0, config.rate_limit.timeout_seconds * 15))
        return max(45.0, min(180.0, config.rate_limit.timeout_seconds * 15))
    if name in {"gitleaks", "trufflehog"}:
        if long_recon:
            return max(60.0, min(600.0, config.rate_limit.timeout_seconds * 8))
        return max(30.0, config.rate_limit.timeout_seconds * 6)
    if long_recon:
        return max(90.0, min(900.0, config.rate_limit.timeout_seconds * 10))
    return min(45.0, max(15.0, config.rate_limit.timeout_seconds * 3))


def command_timeout_error(name: str) -> str:
    if name == "bbot":
        return "tool_hung"
    return "timeout"


def bbot_hang_guard_seconds() -> float | None:
    value = os.environ.get("DONZO_BBOT_HANG_GUARD_SECONDS", "").strip()
    if value:
        try:
            parsed = float(value)
        except ValueError:
            parsed = 900.0
        if parsed <= 0:
            return None
        return max(60.0, parsed)
    return 900.0


def use_tool_default_limits(profile: str | None = None) -> bool:
    return profile == "deep" or env_flag("DONZO_USE_TOOL_DEFAULT_LIMITS")


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def tool_limit_args(*args: str, profile: str | None = None) -> list[str]:
    if use_tool_default_limits(profile):
        return []
    return list(args)


def katana_limit_args(
    config: ScopeConfig,
    timeout: str,
    *,
    profile: str | None = None,
) -> list[str]:
    if use_tool_default_limits(profile):
        return []
    return [
        "-depth",
        str(katana_depth(config)),
        "-timeout",
        timeout,
        "-ct",
        f"{katana_crawl_duration_seconds(config)}s",
        "-mdp",
        str(katana_max_domain_pages(config)),
    ]


def command_timeout_override_seconds(name: str) -> float | None:
    normalized = name.upper().replace("-", "_")
    for env_name in (f"DONZO_COMMAND_TIMEOUT_{normalized}", "DONZO_COMMAND_TIMEOUT"):
        value = os.environ.get(env_name, "").strip()
        if not value:
            continue
        try:
            parsed = float(value)
        except ValueError:
            continue
        if parsed > 0:
            return min(parsed, 1800.0)
    return None


def normalize_optional_command_failure(
    result: dict[str, Any],
    *,
    required_for_run: bool,
) -> dict[str, Any]:
    if not result.get("error"):
        return result
    if result.get("error") in {"timeout", "nonzero_exit"} and result_has_stdout(result):
        normalized = dict(result)
        normalized["partial_output"] = True
        normalized["warning"] = f"partial_output_from_{result['error']}"
        normalized["error"] = None
        return normalized
    if required_for_run:
        return result
    normalized = dict(result)
    normalized["skip_reason"] = f"optional_tool_failed:{result['error']}"
    normalized["skipped"] = True
    normalized["error"] = None
    return normalized


def optional_runtime_skip_reason(
    plan: CommandPlan,
    *,
    required_for_run: bool,
) -> str:
    if required_for_run:
        return ""
    if not plan.allowed:
        return plan_policy_skip_reason(plan)
    if plan.name == "alterx":
        input_path = str(plan.stdin_path) if plan.stdin_path else option_value(plan.argv, "-l")
        if input_path and input_path != "stdin" and not file_has_text(input_path):
            return "empty_input:subfinder"
    if reason := optional_tool_skip_reason(plan.name):
        return reason
    return ""


def plan_policy_skip_reason(plan: CommandPlan) -> str:
    reasons = [reason for reason in plan.reasons if reason != "allowed"]
    if reasons:
        return "policy_blocked:" + ",".join(reasons)
    return "policy_blocked"


def option_value(argv: list[str], option: str) -> str:
    try:
        index = argv.index(option)
    except ValueError:
        return ""
    if index + 1 >= len(argv):
        return ""
    return argv[index + 1]


def file_has_text(path_value: str) -> bool:
    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return False
    try:
        return bool(path.read_text(encoding="utf-8", errors="ignore").strip())
    except OSError:
        return False


def result_has_stdout(result: dict[str, Any]) -> bool:
    path_value = result.get("stdout_path")
    if not path_value:
        return False
    path = Path(str(path_value))
    return path.exists() and path.stat().st_size > 0


def optional_tool_skip_reason(name: str, *, profile: str | None = None) -> str:
    if name == "amass" and profile != "deep" and not os.environ.get("DONZO_ENABLE_AMASS_PASSIVE"):
        return "disabled_by_default:amass_passive_can_hang"
    if name == "bbot" and os.name == "nt" and not os.environ.get("DONZO_FORCE_BBOT"):
        return "unsupported_on_windows:bbot_dependency_requires_fcntl"
    if name == "bbot" and (reason := bbot_core_dependency_skip_reason()):
        return reason
    if name == "uncover" and not uncover_provider_keys_present():
        return "missing_provider_keys:uncover"
    if name == "arjun" and profile != "deep" and not os.environ.get("DONZO_ENABLE_ARJUN_PASSIVE"):
        return "disabled_by_default:arjun_passive_provider_is_flaky"
    return ""


def bbot_core_dependency_skip_reason() -> str:
    if os.environ.get("DONZO_FORCE_BBOT_CORE_DEPS"):
        return ""
    if os.environ.get("BBOT_SUDO_PASS"):
        return ""
    missing = missing_bbot_core_dependencies()
    if not missing:
        return ""
    return "missing_bbot_core_deps:" + ",".join(missing)


def missing_bbot_core_dependencies() -> list[str]:
    missing: list[str] = []
    command_deps = {
        "unzip": "unzip",
        "zipinfo": "zipinfo",
        "7z": "7z",
    }
    for label, binary in command_deps.items():
        if shutil.which(binary) is None:
            missing.append(label)
    if not openssl_dev_headers_present():
        missing.append("openssl_dev_headers")
    return missing


def openssl_dev_headers_present() -> bool:
    candidate_paths = (
        "/usr/include/openssl/ssl.h",
        "/usr/local/include/openssl/ssl.h",
    )
    return any(Path(path).exists() for path in candidate_paths)


def uncover_provider_keys_present() -> bool:
    return bool(uncover_configured_engines())


def uncover_engine_args() -> list[str]:
    engines = uncover_configured_engines()
    if not engines:
        return []
    return ["-e", ",".join(engines)]


def uncover_configured_engines() -> list[str]:
    single_key_providers = (
        ("shodan", ("SHODAN_API_KEY", "SHODAN_KEY")),
        ("quake", ("QUAKE_TOKEN",)),
        ("hunter", ("HUNTER_API_KEY",)),
        ("zoomeye", ("ZOOMEYE_API_KEY",)),
        ("netlas", ("NETLAS_API_KEY",)),
        ("criminalip", ("CRIMINALIP_API_KEY",)),
        ("publicwww", ("PUBLICWWW_API_KEY",)),
        ("hunterhow", ("HUNTERHOW_API_KEY",)),
        ("onyphe", ("ONYPHE_API_KEY",)),
        ("driftnet", ("DRIFTNET_API_KEY",)),
        ("daydaymap", ("DAYDAYMAP_API_KEY",)),
        ("nerdydata", ("NERDYDATA_API_KEY",)),
    )
    paired_providers = (
        (
            "censys",
            (
                ("CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID"),
                ("CENSYS_API_ID", "CENSYS_API_SECRET"),
            ),
        ),
        ("fofa", (("FOFA_EMAIL", "FOFA_KEY"),)),
        ("google", (("GOOGLE_API_KEY", "GOOGLE_API_CX"),)),
    )
    engines: list[str] = []
    for engine, env_names in single_key_providers:
        if any(os.environ.get(name) for name in env_names):
            engines.append(engine)
    for engine, env_pairs in paired_providers:
        if any(all(os.environ.get(name) for name in env_pair) for env_pair in env_pairs):
            engines.append(engine)
    return engines


def root_domains(config: ScopeConfig) -> list[str]:
    roots: list[str] = []
    for domain in config.scope.in_scope_domains:
        normalized = domain[2:] if domain.startswith("*.") else domain
        if normalized not in roots:
            roots.append(normalized)
    return roots


def scope_seed_urls(config: ScopeConfig) -> list[str]:
    candidates: list[str] = []
    for rule in config.scope.in_scope_urls:
        raw = rule.raw.strip()
        if not raw:
            continue
        if "://" not in raw:
            raw = f"https://{raw.lstrip('/')}"
        candidates.append(raw.rstrip("/") or raw)
    if not candidates:
        candidates.extend(f"https://{root}" for root in root_domains(config))
    return allowed_url_values(candidates, config=config)


def scope_seed_hostnames(config: ScopeConfig) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for url in scope_seed_urls(config):
        hostname = (urlparse(url).hostname or "").strip().lower()
        if hostname and hostname not in seen:
            values.append(hostname)
            seen.add(hostname)
    for root in root_domains(config):
        hostname = root.strip().lower()
        if hostname and hostname not in seen:
            values.append(hostname)
            seen.add(hostname)
    return values


def allowed_url_values(values: list[str], *, config: ScopeConfig) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for value in values:
        url = value.strip()
        if not url or url in seen:
            continue
        if config.scope.decide(url).allowed:
            urls.append(url)
            seen.add(url)
    return urls


def active_asset_candidate_limit(config: ScopeConfig) -> int:
    budget = int(config.rate_limit.max_requests_per_second * config.rate_limit.timeout_seconds * 8)
    upper = 800 if os.environ.get("DONZO_LONG_RECON") else 200
    return max(50, min(upper, budget))


def http_probe_asset_limit(config: ScopeConfig) -> int:
    budget = int(config.rate_limit.max_requests_per_second * config.rate_limit.timeout_seconds)
    upper = 120 if os.environ.get("DONZO_LONG_RECON") else 24
    return max(8, min(upper, budget))


def live_url_input_limit(config: ScopeConfig) -> int:
    budget = int(config.rate_limit.max_requests_per_second * config.rate_limit.timeout_seconds)
    upper = 120 if os.environ.get("DONZO_LONG_RECON") else 30
    return max(12, min(upper, budget))


def katana_depth(config: ScopeConfig) -> int:
    default = 2 if os.environ.get("DONZO_LONG_RECON") else 1
    return bounded_env_int("DONZO_KATANA_DEPTH", default, minimum=1, maximum=3)


def katana_crawl_duration_seconds(config: ScopeConfig) -> int:
    upper = 120 if os.environ.get("DONZO_LONG_RECON") else 15
    default = max(5, min(upper, int(config.rate_limit.timeout_seconds)))
    return bounded_env_int("DONZO_KATANA_CRAWL_DURATION", default, minimum=5, maximum=upper)


def katana_max_domain_pages(config: ScopeConfig) -> int:
    upper = 120 if os.environ.get("DONZO_LONG_RECON") else 15
    default = max(5, min(upper, int(config.rate_limit.timeout_seconds)))
    return bounded_env_int("DONZO_KATANA_MAX_DOMAIN_PAGES", default, minimum=5, maximum=upper)


def openapi_schema_probe_limit(config: ScopeConfig) -> int:
    budget = int(config.rate_limit.max_requests_per_second * config.rate_limit.timeout_seconds)
    upper = 20 if os.environ.get("DONZO_LONG_RECON") else 6
    return max(3, min(upper, budget))


def js_network_fetch_limit(config: ScopeConfig) -> int:
    budget = int(config.rate_limit.max_requests_per_second * config.rate_limit.timeout_seconds)
    upper = 20 if os.environ.get("DONZO_LONG_RECON") else 6
    return max(3, min(upper, budget))


def bounded_env_int(env_name: str, default: int, *, minimum: int, maximum: int) -> int:
    value = os.environ.get(env_name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def write_root_domains_file(roots: list[str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(roots) + ("\n" if roots else ""), encoding="utf-8")


def write_candidate_assets_file(
    *,
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
) -> None:
    prioritized_paths = (
        raw_dir / "subfinder.txt",
        raw_dir / "amass.txt",
        raw_dir / "bbot.txt",
        raw_dir / "uncover.txt",
    )
    expansion_paths = (raw_dir / "alterx.txt",)
    candidates: list[str] = root_domains(config)
    for asset_path in prioritized_paths:
        if asset_path.exists():
            candidates.extend(load_text_lines(asset_path))
    for asset_path in expansion_paths:
        if asset_path.exists():
            candidates.extend(load_text_lines(asset_path))
    assets, _removed = normalize_asset_lines(
        candidates,
        config=config,
        source="candidate_assets",
    )
    limit = active_asset_candidate_limit(config)
    values: list[str] = []
    seen: set[str] = set()
    for item in assets:
        value = str(item.get("asset") or "")
        if not value or value in seen or str(item.get("type")) not in {"domain", "host"}:
            continue
        values.append(value)
        seen.add(value)
        if len(values) >= limit:
            break
    output_path = derived_dir / "candidate_assets.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def write_http_probe_asset_inputs(
    *,
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
) -> None:
    candidates: list[str] = scope_seed_hostnames(config)
    dnsx_path = raw_dir / "dnsx.txt"
    dnsx_lines: list[str] = []
    if dnsx_path.exists():
        dnsx_lines = load_text_lines(dnsx_path)
        candidates.extend(dnsx_lines)
    candidate_path = derived_dir / "candidate_assets.txt"
    if not dnsx_lines and candidate_path.exists():
        candidates.extend(load_text_lines(candidate_path))
    assets, _removed = normalize_asset_lines(
        candidates,
        config=config,
        source="http_probe_assets",
    )
    limit = http_probe_asset_limit(config)
    values: list[str] = []
    seen: set[str] = set()
    for item in assets:
        value = str(item.get("asset") or "")
        if not value or value in seen or str(item.get("type")) not in {"domain", "host"}:
            continue
        values.append(value)
        seen.add(value)
        if len(values) >= limit:
            break
    output_path = derived_dir / "http_probe_assets.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def write_archive_url_inputs(
    *,
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
) -> None:
    candidates: list[str] = []
    for archive_path in (
        raw_dir / "gau.txt",
        raw_dir / "waybackurls.txt",
        raw_dir / "waymore.txt",
        raw_dir / "paramspider.txt",
    ):
        if archive_path.exists():
            candidates.extend(load_text_lines(archive_path))
    endpoints, _removed = normalize_endpoint_lines(
        candidates,
        config=config,
        source="archive_url_inputs",
    )
    urls = sorted({str(item.get("url")) for item in endpoints if item.get("url")})
    output_path = derived_dir / "archive_urls.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def write_live_url_inputs(
    *,
    config: ScopeConfig,
    raw_dir: Path,
    derived_dir: Path,
) -> None:
    candidates: list[str] = scope_seed_urls(config)
    candidates.extend(app_seed_urls(config))
    httpx_path = raw_dir / "httpx.jsonl"
    if httpx_path.exists():
        for record in load_jsonl_text(httpx_path.read_text(encoding="utf-8")):
            url = str(record.get("url") or record.get("input") or "")
            if url:
                candidates.append(url)
    archive_path = derived_dir / "archive_urls.txt"
    if archive_path.exists():
        for url in load_text_lines(archive_path):
            origin = url_origin(url)
            if origin:
                candidates.append(origin)
            if not is_static_asset_url(url):
                candidates.append(url)
    urls = allowed_url_values(candidates, config=config)[: live_url_input_limit(config)]
    output_path = derived_dir / "live_urls.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def app_seed_urls(config: ScopeConfig) -> list[str]:
    candidates: list[str] = []
    for seed in scope_seed_urls(config):
        origin = url_origin(seed) or seed.rstrip("/")
        for path in COMMON_APP_BASE_PATHS:
            candidates.append(openapi_url(origin, path))
    return allowed_url_values(candidates, config=config)


def url_origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def is_static_asset_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    static_suffixes = (
        ".css",
        ".eot",
        ".gif",
        ".ico",
        ".jpg",
        ".jpeg",
        ".js",
        ".map",
        ".otf",
        ".png",
        ".svg",
        ".ttf",
        ".wasm",
        ".webmanifest",
        ".woff",
        ".woff2",
    )
    return path.endswith(static_suffixes)


def domain_flag_args(domains: list[str]) -> list[str]:
    args: list[str] = []
    for domain in domains:
        args.extend(["-d", domain])
    return args


def repeated_flag_args(flag: str, values: list[str]) -> list[str]:
    args: list[str] = []
    for value in values:
        args.extend([flag, value])
    return args


def cli_positive_int(value: float | int) -> str:
    return str(max(1, int(float(value))))


def asset_lines_from_json_records(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        for key in ("host", "input", "domain", "dns_name", "name", "subject_cn"):
            value = record.get(key)
            if isinstance(value, str) and value:
                values.append(value)
        for key in ("dns_names", "san", "subject_an", "subject_alt_names"):
            value = record.get(key)
            if isinstance(value, list):
                values.extend(str(item) for item in value if str(item))
            elif isinstance(value, str) and value:
                values.extend(part.strip() for part in value.split(",") if part.strip())
    return values


def port_records_from_json_records(
    records: list[dict[str, Any]],
    *,
    default_port: int,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for record in records:
        host = first_record_text(record, ("host", "input", "domain", "dns_name"))
        if not host:
            continue
        output.append({"host": host, "port": record.get("port") or default_port})
    return output


def first_record_text(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def flow_manifest_from_traffic(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (
            str(record.get("actor") or "unknown"),
            str(record.get("role") or ""),
            str(record.get("tenant") or ""),
            str(record.get("state") or "unknown"),
            str(record.get("flow") or record.get("source_file") or "traffic"),
        )
        item = grouped.setdefault(
            key,
            {
                "actor": key[0],
                "role": key[1],
                "tenant": key[2],
                "state": key[3],
                "flow": key[4],
                "labels": set(),
                "traffic_ids": [],
                "source_files": set(),
                "credential_policy": "safe references only; raw credentials are not persisted",
                "redacted": True,
            },
        )
        if record.get("label"):
            item["labels"].add(str(record.get("label")))
        if record.get("traffic_id"):
            item["traffic_ids"].append(str(record.get("traffic_id")))
        if record.get("source_file"):
            item["source_files"].add(str(record.get("source_file")))
    output: list[dict[str, Any]] = []
    for item in grouped.values():
        labels = sorted(item.pop("labels"))
        source_files = sorted(item.pop("source_files"))
        item["flow_manifest_id"] = stable_id(
            "flow_manifest",
            item.get("actor"),
            item.get("state"),
            item.get("flow"),
            item.get("traffic_ids"),
        )
        item["labels"] = labels
        item["source_files"] = source_files
        item["traffic_count"] = len(item.get("traffic_ids") or [])
        output.append(
            {key: value for key, value in item.items() if value not in (None, "", [], {})}
        )
    return output


def dedupe_by_field(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        value = str(record.get(field) or "")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(record)
    return output


def top_graphql_context(records: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "graphql_operation_id": item.get("graphql_operation_id"),
            "operation_name": item.get("operation_name"),
            "operation_type": item.get("operation_type"),
            "resource": item.get("resource"),
            "action": item.get("action"),
            "variable_names": item.get("variable_names") or [],
            "risk_tags": item.get("risk_tags") or [],
        }
        for item in records[:limit]
    ]


def top_business_context(
    flows: list[dict[str, Any]],
    mutation_plans: list[dict[str, Any]],
    limit: int = 10,
) -> dict[str, Any]:
    return {
        "flows": [
            {
                "business_flow_id": item.get("business_flow_id"),
                "flow_type": item.get("flow_type"),
                "endpoint_ids": item.get("endpoint_ids") or [],
                "confidence": item.get("confidence"),
            }
            for item in flows[:limit]
        ],
        "manual_mutation_strategies": sorted(
            {str(item.get("strategy")) for item in mutation_plans if item.get("strategy")}
        ),
    }


def write_live_urls_from_httpx(input_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not input_path.exists():
        output_path.write_text("", encoding="utf-8")
        return
    urls: list[str] = []
    for record in load_jsonl_text(input_path.read_text(encoding="utf-8")):
        url = str(record.get("url") or record.get("input") or "")
        if url:
            urls.append(url)
    output_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def load_tool_json_records(
    path: Path,
    source: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not path.exists():
        return [], []
    records: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            removed.append(
                {
                    "record": stripped[:500],
                    "source": source,
                    "line_number": line_number,
                    "reason": f"invalid_json:{exc.msg}",
                }
            )
            continue
        if not isinstance(data, dict):
            removed.append(
                {
                    "record": stripped[:500],
                    "source": source,
                    "line_number": line_number,
                    "reason": "invalid_json:not_object",
                }
            )
            continue
        records.append(data)
    return records, removed


def load_tool_json_document_records(
    path: Path,
    source: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not path.exists():
        return [], []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return [], []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return load_tool_json_records(path, source)
    if isinstance(data, dict):
        return [data], []
    if isinstance(data, list):
        records: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        for index, item in enumerate(data, start=1):
            if isinstance(item, dict):
                records.append(item)
            else:
                removed.append(
                    {
                        "record": str(item)[:500],
                        "source": source,
                        "line_number": index,
                        "reason": "invalid_json:not_object",
                    }
                )
        return records, removed
    return (
        [],
        [
            {
                "record": text[:500],
                "source": source,
                "line_number": 1,
                "reason": "invalid_json:not_object",
            }
        ],
    )
