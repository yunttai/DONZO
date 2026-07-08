from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from donzo.analyzers.api_model import build_api_endpoint_models
from donzo.analyzers.dependency_graph import (
    build_api_dependency_graph,
    build_api_sequences,
    build_state_transitions,
)
from donzo.analyzers.discovery import (
    endpoints_from_api_collection_document,
    endpoints_from_robots_text,
    endpoints_from_sitemap_text,
)
from donzo.analyzers.handler_hypothesis import build_handler_hypotheses
from donzo.analyzers.invariants import build_security_invariants
from donzo.analyzers.js import (
    extract_endpoints_from_js_text,
    js_file_endpoints,
    source_map_endpoints,
)
from donzo.analyzers.openapi import (
    api_surface_candidates,
    endpoints_from_openapi_document,
    openapi_document_candidates,
    parse_openapi_document_text,
)
from donzo.analyzers.parameter_classifier import build_parameter_classifications
from donzo.analyzers.schema_diff import build_schema_diffs
from donzo.analyzers.semantics import build_api_semantic_map
from donzo.analyzers.technology import build_technology_inferences
from donzo.candidates.basic import build_basic_candidates
from donzo.cli import RunProgressRenderer, load_project_dotenv, main
from donzo.clustering import cluster_records
from donzo.config import AuthenticatedCrawlConfig, load_scope_config
from donzo.dedupe import dedupe_records
from donzo.normalize.artifacts import (
    normalize_asset_lines,
    normalize_endpoint_lines,
    normalize_endpoint_records,
    normalize_httpx_records,
    normalize_port_records,
    normalize_secret_scan_records,
)
from donzo.oracles.oracle_templates import build_oracle_templates
from donzo.parameters import build_parameters_from_endpoints
from donzo.pipeline import (
    bbot_core_dependency_skip_reason,
    build_llm_triage_input_packs,
    build_recon_command_plans,
    build_run_diff,
    build_tool_preflight,
    command_timeout_error,
    command_timeout_seconds,
    discover_js_static_endpoints,
    discover_openapi_schema_endpoints,
    load_tool_json_document_records,
    load_tool_json_records,
    normalize_optional_command_failure,
    openapi_schema_probe_limit,
    optional_runtime_skip_reason,
    optional_skipped_tools,
    run_deep_recon_commands_parallel,
    run_llm_triage_artifacts,
    scope_seed_urls,
    uncover_configured_engines,
    uncover_provider_keys_present,
    write_archive_url_inputs,
    write_candidate_assets_file,
    write_dashboard_artifacts,
    write_http_probe_asset_inputs,
    write_live_url_inputs,
)
from donzo.planning.test_plans import build_safe_manual_test_plans
from donzo.ranking import rank_records
from donzo.review import build_llm_triage_queue
from donzo.runner import CommandResult, build_command_plan, run_command_plan
from donzo.storage.jsonl import load_json_records, write_jsonl
from donzo.tools import check_tools, tool_matrix
from donzo.traffic.har_ingest import endpoint_records_from_traffic, ingest_har_file
from donzo.verification import verify_candidates
from donzo.verification.probe import ProbeResult, probe_url


def test_endpoint_normalize_candidate_rank_pipeline() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    records = load_json_records(Path("harness/fixtures/sample-artifacts/endpoints.json"))
    endpoints, removed = normalize_endpoint_records(records, config=config, source="fixture")
    assert removed == []
    assert "object_resource" in endpoints[0]["risk_hints"]
    assert "api_route" in endpoints[0]["risk_hints"]

    candidates = build_basic_candidates(endpoints)
    assert candidates[0]["candidate_type"] == "BOLA_IDOR"
    assert candidates[0]["auto_exploit"] is False

    ranked = rank_records(candidates)
    assert ranked[0]["priority"] in {"P1", "P2", "P3"}
    assert ranked[0]["risk_score"] > 0


def test_parameter_candidates_are_manual_review_only() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = normalize_endpoint_records(
        [
            {"url": "https://api.example.com/fetch?url=https://example.com", "method": "GET"},
            {"url": "https://app.example.com/login?next=/dashboard", "method": "GET"},
        ],
        config=config,
        source="fixture",
    )
    assert removed == []
    params = build_parameters_from_endpoints(endpoints)
    assert {item["name"] for item in params} == {"url", "next"}

    candidates = build_basic_candidates(endpoints)
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {"SSRF", "OPEN_REDIRECT"}.issubset(candidate_types)
    assert all(item["auto_exploit"] is False for item in candidates)


def test_technology_inference_extracts_backend_and_api_hints() -> None:
    services, removed = normalize_httpx_records(
        [
            {
                "url": "https://app.example.com/admin",
                "status_code": 200,
                "title": "Grafana",
                "webserver": "nginx",
                "tech": ["Grafana", "React"],
                "jarm": "fixture-jarm",
            }
        ],
        config=load_scope_config(Path("scope.example.yaml")),
    )
    endpoints, endpoint_removed = normalize_endpoint_records(
        [
            {
                "url": "https://app.example.com/api/users",
                "method": "GET",
                "status_code": 200,
            }
        ],
        config=load_scope_config(Path("scope.example.yaml")),
        source="fixture",
    )

    inferences = build_technology_inferences(
        services=services,
        endpoints=endpoints,
        tlsx_records=[{"host": "app.example.com", "issuer_cn": "Fixture CA"}],
    )

    assert removed == []
    assert endpoint_removed == []
    assert inferences
    names = {tech["name"] for tech in inferences[0]["technologies"]}
    assert {"grafana", "nginx"}.issubset(names)
    assert {hint["hint"] for hint in inferences[0]["api_hints"]} >= {"/api", "api_route"}


def test_admin_panel_candidate_is_manual_review_only() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = normalize_endpoint_records(
        [
            {
                "url": "https://app.example.com/admin",
                "method": "GET",
                "title": "Grafana",
                "tech": ["Grafana"],
            }
        ],
        config=config,
        source="httpx",
    )

    candidates = build_basic_candidates(endpoints)

    assert removed == []
    admin = next(item for item in candidates if item["candidate_type"] == "ADMIN_PANEL")
    assert admin["auto_exploit"] is False
    assert "brute force" in " ".join(admin["manual_verification"]).lower()


def test_archive_urls_generate_api_graphql_and_redirect_candidates() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    lines = (
        Path("harness/fixtures/sample-artifacts/archive-urls.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    endpoints, removed = normalize_endpoint_lines(lines, config=config, source="archive")
    assert {item["url"] for item in endpoints} == {
        "https://api.example.com/v3/api-docs",
        "https://api.example.com/graphql",
        "https://app.example.com/login?next=/dashboard",
    }
    assert removed[0]["reason"] == "matched_in_scope; matched_out_of_scope"

    candidates = build_basic_candidates(endpoints)
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {"EXPOSED_API_DOCS", "GRAPHQL", "OPEN_REDIRECT"}.issubset(candidate_types)
    assert all(item["auto_exploit"] is False for item in candidates)
    clusters = cluster_records(rank_records(candidates))
    assert {"API_DOCS", "GRAPHQL", "OPEN_REDIRECT"}.issubset(
        {item["cluster_type"] for item in clusters}
    )


def test_verification_filters_auth_bola_false_positive() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = normalize_endpoint_records(
        [
            {"url": "https://app.example.com/accounts/login/", "method": "GET"},
            {"url": "https://app.example.com/api/v1/orders/123", "method": "GET"},
        ],
        config=config,
        source="fixture",
    )
    assert removed == []
    candidates = build_basic_candidates(endpoints)
    result = verify_candidates(candidates, config=config, endpoints=endpoints, network=False)

    assert [item["filter_reason"] for item in result.filtered] == ["auth_endpoint_not_bola"]
    assert {item["target"] for item in result.candidates} == {
        "https://app.example.com/api/v1/orders/123"
    }
    assert result.summary["filtered_candidates"] == 1


def test_probe_url_enforces_connect_deadline(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(config.verification.probe, timeout_seconds=0.01),
        ),
    )

    class FakeSocket:
        def setblocking(self, _value):
            return None

        def connect_ex(self, _sockaddr):
            return 10036

        def close(self):
            return None

    monkeypatch.setattr(
        "donzo.verification.probe.socket.getaddrinfo",
        lambda *args, **kwargs: [(0, 0, 0, "", ("203.0.113.1", 80))],
    )
    monkeypatch.setattr("donzo.verification.probe.socket.socket", lambda *args: FakeSocket())
    monkeypatch.setattr(
        "donzo.verification.probe.select.select",
        lambda readers, writers, errors, timeout: ([], [], []),
    )

    result = probe_url("http://example.com/hang", config=config)

    assert result.status_code is None
    assert result.error_signature == "timeout"


def test_verification_confirms_api_docs_from_probe_metadata() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    candidate = {
        "candidate_type": "EXPOSED_API_DOCS",
        "target": "https://api.example.com/openapi.json",
        "severity": "medium",
        "confidence": 0.4,
        "source": ["test"],
        "reason": ["test"],
        "manual_verification": ["Confirm manually."],
        "auto_exploit": False,
    }
    endpoint = {
        "url": "https://api.example.com/openapi.json",
        "method": "GET",
        "status_code": 200,
        "content_type": "application/json",
        "title": "",
    }
    result = verify_candidates([candidate], config=config, endpoints=[endpoint], network=False)

    assert result.candidates[0]["verification_status"] == "needs_manual_review"
    assert result.summary["reviewable_candidates"] == 1


def test_verification_filters_source_map_html_error() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    candidate = {
        "candidate_type": "SOURCE_MAP_EXPOSURE",
        "target": "https://app.example.com/assets/app.js.map",
        "severity": "low",
        "confidence": 0.5,
        "source": ["test"],
        "reason": ["test"],
        "manual_verification": ["Confirm manually."],
        "auto_exploit": False,
    }
    endpoint = {
        "url": "https://app.example.com/assets/app.js.map",
        "method": "GET",
        "status_code": 200,
        "content_type": "text/html",
        "title": "Page Not Found",
    }
    result = verify_candidates([candidate], config=config, endpoints=[endpoint], network=False)

    assert result.filtered[0]["filter_reason"] in {
        "not_actual_sourcemap",
        "soft_404_common_error",
    }


def test_verification_network_probe_budget_caps_live_requests(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(config.verification.probe, max_network_probes=2),
            soft404=replace(config.verification.soft404, enabled=False),
        ),
    )
    candidates = [
        {
            "candidate_type": "EXPOSED_API_DOCS",
            "target": f"https://api.example.com/openapi-{index}.json",
            "severity": "medium",
            "confidence": 0.4,
            "source": ["test"],
            "reason": ["test"],
            "manual_verification": ["Confirm manually."],
            "auto_exploit": False,
        }
        for index in range(5)
    ]
    calls: list[str] = []

    def fake_probe(url: str, **_kwargs) -> ProbeResult:
        calls.append(url)
        return ProbeResult(
            probe_id=f"probe-{len(calls)}",
            url=url,
            method="GET",
            status_code=404,
            final_url=url,
            content_type="text/html",
            body_text="not found",
        )

    monkeypatch.setattr("donzo.verification.pipeline.probe_url", fake_probe)

    result = verify_candidates(candidates, config=config, endpoints=[], network=True)

    assert len(calls) == 2
    assert result.summary["network_probe_budget"] == {
        "limit": 2,
        "unlimited": False,
        "used": 2,
        "exhausted": True,
    }
    assert len(result.candidates) == 3
    assert {item["evidence"]["verification"]["reason"] for item in result.candidates} == {
        "probe_budget_exhausted"
    }


def test_verification_network_probe_budget_zero_means_unlimited(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(config.verification.probe, max_network_probes=0),
            soft404=replace(config.verification.soft404, enabled=False),
        ),
    )
    candidates = [
        {
            "candidate_type": "EXPOSED_API_DOCS",
            "target": f"https://api.example.com/openapi-{index}.json",
            "severity": "medium",
            "confidence": 0.4,
            "source": ["test"],
            "reason": ["test"],
            "manual_verification": ["Confirm manually."],
            "auto_exploit": False,
        }
        for index in range(5)
    ]
    calls: list[str] = []

    def fake_probe(url: str, **_kwargs) -> ProbeResult:
        calls.append(url)
        return ProbeResult(
            probe_id=f"probe-{len(calls)}",
            url=url,
            method="GET",
            status_code=404,
            final_url=url,
            content_type="text/html",
            body_text="not found",
        )

    monkeypatch.setattr("donzo.verification.pipeline.probe_url", fake_probe)

    result = verify_candidates(candidates, config=config, endpoints=[], network=True)

    assert len(calls) == 5
    assert result.summary["network_probe_budget"] == {
        "limit": 0,
        "unlimited": True,
        "used": 5,
        "exhausted": False,
    }


def test_verification_origin_timeout_cache_skips_repeated_dead_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(config.verification.probe, max_network_probes=10),
            soft404=replace(config.verification.soft404, enabled=False),
        ),
    )
    monkeypatch.setenv("DONZO_ORIGIN_TIMEOUT_THRESHOLD", "2")
    candidates = [
        {
            "candidate_type": "EXPOSED_API_DOCS",
            "target": f"https://api.example.com/openapi-{index}.json",
            "severity": "medium",
            "confidence": 0.4,
            "source": ["test"],
            "reason": ["test"],
            "manual_verification": ["Confirm manually."],
            "auto_exploit": False,
        }
        for index in range(5)
    ]
    calls: list[str] = []

    def fake_probe(url: str, **_kwargs) -> ProbeResult:
        calls.append(url)
        return ProbeResult(
            probe_id=f"probe-{len(calls)}",
            url=url,
            method="GET",
            status_code=None,
            final_url=url,
            error_signature="timeout",
        )

    monkeypatch.setattr("donzo.verification.pipeline.probe_url", fake_probe)

    result = verify_candidates(candidates, config=config, endpoints=[], network=True)

    assert len(calls) == 2
    assert result.summary["network_probe_budget"]["used"] == 2
    assert result.summary["origin_timeout_cache"]["skipped_probes"] == 3
    assert result.summary["origin_timeout_cache"]["origins"] == {"https://api.example.com": 2}
    assert (
        sum(1 for probe in result.probes if probe.get("error_signature") == "origin_timeout_cached")
        == 3
    )
    reasons = [item["evidence"]["verification"]["reason"] for item in result.candidates]
    assert reasons.count("probe_timeout") == 2
    assert reasons.count("origin_timeout_cached") == 3


def test_verification_origin_timeout_cache_can_be_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(
                config.verification.probe,
                max_network_probes=10,
                origin_timeout_threshold=0,
            ),
            soft404=replace(config.verification.soft404, enabled=False),
        ),
    )
    monkeypatch.delenv("DONZO_ORIGIN_TIMEOUT_THRESHOLD", raising=False)
    candidates = [
        {
            "candidate_type": "EXPOSED_API_DOCS",
            "target": f"https://api.example.com/openapi-{index}.json",
            "severity": "medium",
            "confidence": 0.4,
            "source": ["test"],
            "reason": ["test"],
            "manual_verification": ["Confirm manually."],
            "auto_exploit": False,
        }
        for index in range(5)
    ]
    calls: list[str] = []

    def fake_probe(url: str, **_kwargs) -> ProbeResult:
        calls.append(url)
        return ProbeResult(
            probe_id=f"probe-{len(calls)}",
            url=url,
            method="GET",
            status_code=None,
            final_url=url,
            error_signature="timeout",
        )

    monkeypatch.setattr("donzo.verification.pipeline.probe_url", fake_probe)

    result = verify_candidates(candidates, config=config, endpoints=[], network=True)

    assert len(calls) == 5
    assert result.summary["origin_timeout_cache"]["threshold"] == 0
    assert result.summary["origin_timeout_cache"]["skipped_probes"] == 0
    assert result.summary["unverified_reason_counts"] == {"probe_timeout": 5}


def test_verification_progress_reports_candidate_and_probe_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        verification=replace(
            config.verification,
            probe=replace(config.verification.probe, max_network_probes=3),
            soft404=replace(config.verification.soft404, enabled=False),
        ),
    )
    candidates = [
        {
            "candidate_type": "EXPOSED_API_DOCS",
            "target": f"https://api.example.com/openapi-{index}.json",
            "severity": "medium",
            "confidence": 0.4,
            "source": ["test"],
            "reason": ["test"],
            "manual_verification": ["Confirm manually."],
            "auto_exploit": False,
        }
        for index in range(3)
    ]

    def fake_probe(url: str, **_kwargs) -> ProbeResult:
        return ProbeResult(
            probe_id=f"probe-{url}",
            url=url,
            method="GET",
            status_code=404,
            final_url=url,
            error_signature=None,
        )

    events: list[dict[str, object]] = []
    monkeypatch.setattr("donzo.verification.pipeline.probe_url", fake_probe)

    verify_candidates(
        candidates,
        config=config,
        endpoints=[],
        network=True,
        progress_callback=events.append,
    )

    assert events[0]["processed"] == 0
    assert events[-1]["processed"] == 3
    assert events[-1]["total"] == 3
    assert events[-1]["probe_used"] == 3
    assert events[-1]["percent"] == 100


def test_js_static_analysis_extracts_scoped_endpoints() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    text = Path("harness/fixtures/sample-artifacts/app.js").read_text(encoding="utf-8")
    endpoints, removed = extract_endpoints_from_js_text(
        text,
        base_url="https://app.example.com",
        config=config,
        source="js_fixture",
    )
    urls = {item["url"] for item in endpoints}
    assert "https://app.example.com/api/v1/orders/123" in urls
    assert "https://app.example.com/graphql" in urls
    assert "https://api.example.com/api/v1/users?id=123" in urls
    assert "https://app.example.com/assets/app.bundle.js" in urls
    assert "https://app.example.com/assets/logo.png" not in urls
    assert removed == []

    source_maps, source_map_removed = source_map_endpoints(
        js_file_endpoints(endpoints),
        config=config,
    )
    assert source_map_removed == []
    assert source_maps[0]["url"] == "https://app.example.com/assets/app.bundle.js.map"

    candidates = build_basic_candidates(endpoints + source_maps)
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {"BOLA_IDOR", "GRAPHQL", "OPEN_REDIRECT", "SOURCE_MAP_EXPOSURE"}.issubset(
        candidate_types
    )


def test_js_static_analysis_keeps_templates_and_methods() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    text = """
    const userId = 123;
    axios.post(`/api/v2/users/${userId}/sessions`, {});
    fetch("/api/v2/files", { method: "DELETE" });
    const cdn = "https://cdn.example.com/assets/logo.png";
    """
    endpoints, removed = extract_endpoints_from_js_text(
        text,
        base_url="https://app.example.com",
        config=config,
        source="js_fixture",
    )

    by_url = {item["url"]: item for item in endpoints}
    assert removed == []
    assert by_url["https://app.example.com/api/v2/users/{userId}/sessions"]["method"] == "POST"
    assert by_url["https://app.example.com/api/v2/files"]["method"] == "DELETE"
    assert "https://cdn.example.com/assets/logo.png" not in by_url


def test_js_static_analysis_preserves_callsite_for_api_semantics() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    text = """
    async function loadCourseMembers(courseId) {
      return api.get(`/api/courses/${courseId}/members`);
    }
    """

    endpoints, removed = extract_endpoints_from_js_text(
        text,
        base_url="https://app.example.com",
        config=config,
        source="js_fixture",
    )
    semantic_map = build_api_semantic_map(endpoints, config=config)

    assert removed == []
    assert endpoints[0]["source_context"]["js_callsite"] == "loadCourseMembers"
    assert semantic_map[0]["resource"] == "course"
    assert semantic_map[0]["action"] == "read"
    assert semantic_map[0]["auth_guess"] == "member_or_owner"
    assert "courseid" in semantic_map[0]["object_id_params"]
    assert "members" in semantic_map[0]["relationship_hints"]
    assert semantic_map[0]["risk_questions"]


def test_openapi_analysis_extracts_parameters_and_candidates() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    document = json.loads(Path("harness/fixtures/sample-artifacts/openapi.json").read_text())
    endpoints, removed = endpoints_from_openapi_document(
        document,
        base_url="https://api.example.com",
        config=config,
        source="openapi_fixture",
    )
    urls = {item["url"] for item in endpoints}
    assert "https://api.example.com/api/v1/orders/{order_id}" in urls
    assert "https://api.example.com/graphql" in urls
    assert "https://api.example.com/files" in urls
    assert any(item["reason"] == "matched_in_scope; matched_out_of_scope" for item in removed)

    params = build_parameters_from_endpoints(endpoints)
    assert {"order_id", "filename"}.issubset({item["name"] for item in params})
    candidate_types = {item["candidate_type"] for item in build_basic_candidates(endpoints)}
    assert {"BOLA_IDOR", "GRAPHQL", "FILE_DISCLOSURE"}.issubset(candidate_types)

    discovered, discovery_removed = openapi_document_candidates(endpoints, config=config)
    assert discovery_removed == []
    assert any(item["url"].endswith("/swagger-ui/index.html") for item in discovered)


def test_openapi_analysis_uses_servers_path_params_and_request_body() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    document = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/v2/users/{user_id}/notes": {
                "parameters": [{"name": "user_id", "in": "path"}],
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "redirect_uri": {"type": "string"},
                                        "filename": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                },
            }
        },
    }

    endpoints, removed = endpoints_from_openapi_document(
        document,
        base_url="https://api.example.com",
        config=config,
        source="openapi_fixture",
    )

    assert removed == []
    assert endpoints[0]["url"] == "https://api.example.com/api/v2/users/{user_id}/notes"
    assert endpoints[0]["method"] == "POST"
    assert {"user_id", "redirect_uri", "filename"}.issubset(set(endpoints[0]["params"]))


def test_openapi_semantic_map_uses_operation_metadata_and_ids() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    approve_path = (
        "/api/courses/{courseId}/assignments/{assignmentId}/submissions/{submissionId}/approve"
    )
    document = {
        "openapi": "3.0.0",
        "paths": {
            approve_path: {
                "patch": {
                    "operationId": "approveSubmission",
                    "tags": ["Submissions"],
                    "summary": "Approve a student submission",
                    "parameters": [
                        {"name": "courseId", "in": "path"},
                        {"name": "assignmentId", "in": "path"},
                        {"name": "submissionId", "in": "path"},
                    ],
                }
            }
        },
    }

    endpoints, removed = endpoints_from_openapi_document(
        document,
        base_url="https://api.example.com",
        config=config,
        source="openapi_fixture",
    )
    semantic_map = build_api_semantic_map(endpoints, config=config)

    assert removed == []
    assert endpoints[0]["operation_id"] == "approveSubmission"
    assert endpoints[0]["operation_tags"] == ["Submissions"]
    assert endpoints[0]["source_context"]["openapi_path"].endswith("/approve")
    assert semantic_map[0]["resource"] == "submission"
    assert semantic_map[0]["action"] == "approve"
    assert semantic_map[0]["auth_guess"] == "owner_or_authorized_actor"
    assert {"courseid", "assignmentid", "submissionid"}.issubset(
        set(semantic_map[0]["object_id_params"])
    )
    assert semantic_map[0]["risk_weight"] >= 55
    assert any("ownership" in question for question in semantic_map[0]["risk_questions"])


def test_har_ingest_redacts_and_infers_schema_models() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    traffic, request_schemas, response_schemas, removed = ingest_har_file(
        Path("harness/fixtures/sample-artifacts/traffic.har"),
        config=config,
        actor="user_A",
        state="logged_in",
        source="har_fixture",
    )
    endpoints, endpoint_removed = normalize_endpoint_records(
        endpoint_records_from_traffic(traffic),
        config=config,
        source="har_fixture",
    )
    semantic_map = build_api_semantic_map(endpoints, config=config)
    api_models = build_api_endpoint_models(
        endpoints,
        traffic=traffic,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        api_semantic_map=semantic_map,
    )
    classifications = build_parameter_classifications(
        api_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    schema_diffs = build_schema_diffs(
        api_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )

    assert removed == []
    assert endpoint_removed == []
    assert len(traffic) == 3
    assert traffic[0]["request"]["headers"]["authorization"] == "[REDACTED]"
    assert traffic[0]["request"]["headers"]["cookie"] == "[REDACTED]"
    assert traffic[0]["response"]["body_sample_redacted"]["email"] == "[EMAIL]"
    assert {item["schema_kind"] for item in request_schemas + response_schemas} == {
        "request",
        "response",
    }
    model_by_template = {item["path_template"]: item for item in api_models}
    assert "/api/v1/orgs/{orgId}/invoices/{invoiceId}" in model_by_template
    assert model_by_template["/api/v1/orgs/{orgId}/invoices/{invoiceId}"]["path_params"] == [
        "orgId",
        "invoiceId",
    ]
    invoice_classification = next(
        item
        for item in classifications
        if item["path_template"] == "/api/v1/orgs/{orgId}/invoices/{invoiceId}"
    )
    semantic_classes = {
        parameter["name"]: parameter["semantic_class"]
        for parameter in invoice_classification["parameters"]
    }
    assert semantic_classes["orgId"] == "tenant_identifier"
    assert semantic_classes["invoiceId"] == "object_identifier"
    assert any(item["mass_assignment_candidates"] for item in schema_diffs)
    assert any(item["excessive_data_candidates"] for item in schema_diffs)


def test_endpoint_dedupe_preserves_same_url_different_methods() -> None:
    records = dedupe_records(
        [
            {
                "endpoint_id": "GET https://app.example.com/api/v1/users/me",
                "method": "GET",
                "url": "https://app.example.com/api/v1/users/me",
            },
            {
                "endpoint_id": "PATCH https://app.example.com/api/v1/users/me",
                "method": "PATCH",
                "url": "https://app.example.com/api/v1/users/me",
            },
        ]
    )

    assert [item["method"] for item in records] == ["GET", "PATCH"]


def test_api_modeling_generates_invariants_test_plans_and_oracles() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    traffic, request_schemas, response_schemas, _removed = ingest_har_file(
        Path("harness/fixtures/sample-artifacts/traffic.har"),
        config=config,
        actor="user_A",
        state="logged_in",
        source="har_fixture",
    )
    endpoints, _endpoint_removed = normalize_endpoint_records(
        endpoint_records_from_traffic(traffic),
        config=config,
        source="har_fixture",
    )
    semantic_map = build_api_semantic_map(endpoints, config=config)
    api_models = build_api_endpoint_models(
        endpoints,
        traffic=traffic,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
        api_semantic_map=semantic_map,
    )
    classifications = build_parameter_classifications(
        api_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    schema_diffs = build_schema_diffs(
        api_models,
        request_schemas=request_schemas,
        response_schemas=response_schemas,
    )
    dependency_graph = build_api_dependency_graph(
        api_models,
        traffic=traffic,
        parameter_classifications=classifications,
    )
    sequences = build_api_sequences(traffic, api_models)
    state_transitions = build_state_transitions(sequences)
    handler_hypotheses = build_handler_hypotheses(
        api_models,
        parameter_classifications=classifications,
        dependency_graph=dependency_graph,
        schema_diffs=schema_diffs,
    )
    invariants = build_security_invariants(
        api_models,
        handler_hypotheses=handler_hypotheses,
        parameter_classifications=classifications,
        schema_diffs=schema_diffs,
        dependency_graph=dependency_graph,
    )
    test_plans = build_safe_manual_test_plans(invariants, api_endpoint_models=api_models)
    oracle_templates = build_oracle_templates(test_plans)

    assert dependency_graph["summary"]["node_count"] >= 3
    assert sequences and sequences[0]["steps"]
    assert state_transitions
    assert any(item["missing_check_candidates"] for item in handler_hypotheses)
    assert {item["type"] for item in invariants} >= {
        "tenant_isolation",
        "object_ownership",
        "field_allowlist",
        "response_minimization",
    }
    assert all(item["safety"]["automatic_exploit"] is False for item in test_plans)
    assert {item["oracle_type"] for item in oracle_templates}


def test_parse_openapi_document_text_accepts_yaml() -> None:
    document = parse_openapi_document_text(
        """
        openapi: 3.0.0
        paths:
          /api/v1/users:
            get:
              parameters:
                - name: user_id
                  in: query
        """,
        "application/yaml",
    )

    assert document is not None
    assert "/api/v1/users" in document["paths"]


def test_openapi_network_discovery_extracts_schema_endpoints(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = normalize_endpoint_records(
        [{"url": "https://api.example.com", "method": "GET"}],
        config=config,
        source="fixture",
    )
    assert removed == []

    def fake_probe(url: str, *, config, method: str = "GET") -> ProbeResult:
        if url == "https://api.example.com/openapi.json":
            return ProbeResult(
                probe_id="probe-openapi",
                url=url,
                method=method,
                status_code=200,
                final_url=url,
                content_type="application/json",
                body_text=json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {
                            "/api/v1/orders/{order_id}": {
                                "get": {
                                    "parameters": [
                                        {"name": "order_id", "in": "path"},
                                        {"name": "include", "in": "query"},
                                    ]
                                }
                            }
                        },
                    }
                ),
            )
        return ProbeResult(
            probe_id="probe-miss",
            url=url,
            method=method,
            status_code=404,
            final_url=url,
            content_type="text/html",
        )

    monkeypatch.setattr("donzo.pipeline.probe_url", fake_probe)

    schema_endpoints, schema_docs, schema_removed = discover_openapi_schema_endpoints(
        endpoints,
        config=config,
    )

    assert {item["url"] for item in schema_docs} == {"https://api.example.com/openapi.json"}
    assert schema_endpoints[0]["url"] == "https://api.example.com/api/v1/orders/{order_id}"
    assert {"order_id", "include"}.issubset(set(schema_endpoints[0]["params"]))
    assert any(item["reason"] == "openapi_schema_not_found" for item in schema_removed)


def test_openapi_network_discovery_has_total_probe_budget(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints = [
        {"url": f"https://api{index}.example.com/v1/users", "method": "GET"} for index in range(50)
    ]
    calls: list[str] = []

    def fake_probe(url: str, *, config, method: str = "GET") -> ProbeResult:
        calls.append(url)
        return ProbeResult(
            probe_id=f"probe-{len(calls)}",
            url=url,
            method=method,
            status_code=404,
            final_url=url,
            content_type="text/html",
        )

    monkeypatch.setattr("donzo.pipeline.probe_url", fake_probe)

    schema_endpoints, schema_docs, schema_removed = discover_openapi_schema_endpoints(
        endpoints,
        config=config,
    )

    assert schema_endpoints == []
    assert schema_docs == []
    assert len(calls) == openapi_schema_probe_limit(config)
    assert len(schema_removed) == openapi_schema_probe_limit(config)


def test_js_network_discovery_extracts_bundle_endpoints(monkeypatch) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    js_files, removed = normalize_endpoint_records(
        [{"url": "https://app.example.com/assets/app.js", "method": "GET"}],
        config=config,
        source="fixture",
    )
    assert removed == []

    def fake_probe(url: str, *, config, method: str = "GET") -> ProbeResult:
        return ProbeResult(
            probe_id="probe-js",
            url=url,
            method=method,
            status_code=200,
            final_url=url,
            content_type="application/javascript",
            body_text='fetch("/api/v1/users"); api.post("/api/v1/orders", {method:"POST"});',
        )

    monkeypatch.setattr("donzo.pipeline.probe_url", fake_probe)

    endpoints, js_removed = discover_js_static_endpoints(js_files, config=config)

    urls = {item["url"] for item in endpoints}
    assert "https://app.example.com/api/v1/users" in urls
    assert "https://app.example.com/api/v1/orders" in urls
    assert js_removed == []


def test_naabu_port_records_are_scope_filtered() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    services, removed = normalize_port_records(
        [
            {"host": "api.example.com", "port": 8080},
            {"host": "payments.example.com", "port": 443},
            {"host": "api.example.com"},
        ],
        config=config,
    )
    assert services[0]["url"] == "http://api.example.com:8080"
    assert services[0]["ports"] == [8080]
    assert "dev_http_port" in services[0]["risk_hints"]
    assert [item["reason"] for item in removed] == [
        "matched_in_scope; matched_out_of_scope",
        "missing host or port",
    ]


def test_normalize_removes_out_of_scope_endpoint() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = normalize_endpoint_records(
        [{"url": "https://payments.example.com/api/v1/orders/123", "method": "GET"}],
        config=config,
        source="fixture",
    )
    assert endpoints == []
    assert removed[0]["reason"] == "matched_in_scope; matched_out_of_scope"


def test_asset_normalize_removes_out_of_scope_domain() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    assets, removed = normalize_asset_lines(
        ["api.example.com", "payments.example.com"],
        config=config,
        source="fixture",
    )
    assert [item["asset"] for item in assets] == ["api.example.com"]
    assert assets[0]["risk_hints"] == ["api_asset"]
    assert removed[0]["reason"] == "matched_in_scope; matched_out_of_scope"


def test_runner_blocks_out_of_scope_target() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plan = build_command_plan(
        config=config,
        name="httpx",
        argv=["httpx", "-json"],
        output_path=Path("artifacts/recon/httpx.jsonl"),
        targets=["https://payments.example.com"],
        required_policy_flag="active_recon",
    )
    assert plan.allowed is False
    assert "target_not_allowed:https://payments.example.com" in plan.reasons


def test_cli_run_fixture_writes_outputs(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "out"
    code = main(
        [
            "run-fixture",
            "-c",
            "scope.example.yaml",
            "--endpoints",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["candidate_count"] == 1
    assert (out_dir / "assets.jsonl").exists()
    assert (out_dir / "services.jsonl").exists()
    assert (out_dir / "endpoints.jsonl").exists()
    assert (out_dir / "params.jsonl").exists()
    assert (out_dir / "api-docs.jsonl").exists()
    assert (out_dir / "graphql-endpoints.jsonl").exists()
    assert (out_dir / "source-maps.jsonl").exists()
    assert (out_dir / "port-services.jsonl").exists()
    assert (out_dir / "candidates.jsonl").exists()
    assert (out_dir / "findings.jsonl").exists()
    assert (out_dir / "ranked.jsonl").exists()
    assert (out_dir / "clusters.jsonl").exists()
    assert (out_dir / "recon-result.json").exists()
    assert (out_dir / "report.md").exists()
    assert result["cluster_count"] == 1
    assert result["evidence_notes"] == 1
    assert list((out_dir / "evidence").glob("*/notes.md"))
    assert "Bug Bounty Recon Report" in (out_dir / "report.md").read_text(encoding="utf-8")


def test_cli_run_fixture_normal_uses_archive_urls(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "normal-fixture"
    code = main(
        [
            "run-fixture",
            "-c",
            "scope.example.yaml",
            "-p",
            "normal",
            "--endpoints",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "--archive-urls",
            "harness/fixtures/sample-artifacts/archive-urls.txt",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["profile"] == "normal"
    assert result["endpoint_count"] >= 10
    assert result["api_doc_count"] >= 7
    assert result["graphql_endpoint_count"] >= 1
    assert result["removed_count"] == 1
    candidates = load_json_records(out_dir / "candidates.jsonl")
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {"BOLA_IDOR", "EXPOSED_API_DOCS", "GRAPHQL", "OPEN_REDIRECT"}.issubset(candidate_types)
    report = (out_dir / "report.md").read_text(encoding="utf-8")
    assert "Artifact Summary" in report
    assert "Cluster Summary" in report
    assert "Manual Verification Queue" in report


def test_cli_run_fixture_normal_uses_js_and_openapi(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "normal-static-fixture"
    code = main(
        [
            "run-fixture",
            "-c",
            "scope.example.yaml",
            "-p",
            "normal",
            "--endpoints",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "--js-file",
            "harness/fixtures/sample-artifacts/app.js",
            "--js-base-url",
            "https://app.example.com",
            "--openapi",
            "harness/fixtures/sample-artifacts/openapi.json",
            "--openapi-base-url",
            "https://api.example.com",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["profile"] == "normal"
    assert result["endpoint_count"] >= 6
    assert result["source_map_count"] == 1
    assert result["api_doc_count"] >= 7
    assert result["graphql_endpoint_count"] >= 1
    assert result["removed_count"] >= 1
    candidates = load_json_records(out_dir / "candidates.jsonl")
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {
        "BOLA_IDOR",
        "GRAPHQL",
        "OPEN_REDIRECT",
        "FILE_DISCLOSURE",
        "SOURCE_MAP_EXPOSURE",
    }.issubset(candidate_types)
    assert (out_dir / "api-docs.jsonl").exists()
    assert (out_dir / "graphql-endpoints.jsonl").exists()
    assert (out_dir / "source-maps.jsonl").exists()


def test_cli_run_fast_dry_run_writes_plan(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "fast"
    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "fast",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["result"]["execute"] is False
    assert result["result"]["tool_preflight"]["profile"] == "fast"
    assert (out_dir / "plan.json").exists()
    assert (out_dir / "tool-preflight.json").exists()
    assert (out_dir / "state.json").exists()
    plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    state = json.loads((out_dir / "state.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in plan["plans"]] == ["subfinder", "dnsx", "httpx", "katana"]
    assert all(item["dry_run"] is True for item in plan["plans"])
    assert plan["tool_preflight"]["tool_count"] == 4
    assert state["status"] == "planned"
    assert state["phase"] == "dry_run"
    assert state["counters"]["planned_commands"] == 4


def test_cli_run_defaults_required_llm_to_external_triage(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_pipeline(**kwargs):
        captured.update(kwargs)
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        return {"execute": kwargs["execute"], "profile": kwargs["profile"]}

    monkeypatch.setattr("donzo.cli.run_recon_pipeline", fake_pipeline)

    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "fast",
            "-o",
            str(tmp_path / "llm-default"),
            "--no-progress",
        ]
    )
    capsys.readouterr()

    assert code == 0
    assert captured["llm_triage"] is True
    assert captured["allow_external_llm"] is True
    assert captured["llm_limit"] == 0


def test_cli_run_can_disable_default_llm_triage(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_pipeline(**kwargs):
        captured.update(kwargs)
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        return {"execute": kwargs["execute"], "profile": kwargs["profile"]}

    monkeypatch.setattr("donzo.cli.run_recon_pipeline", fake_pipeline)

    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "fast",
            "-o",
            str(tmp_path / "llm-disabled"),
            "--no-llm-triage",
            "--no-external-llm",
            "--no-progress",
        ]
    )
    capsys.readouterr()

    assert code == 0
    assert captured["llm_triage"] is False
    assert captured["allow_external_llm"] is False


def test_cli_run_failure_writes_error_artifacts(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    out_dir = tmp_path / "failed-run"

    def fail_pipeline(**kwargs):
        output_dir = kwargs["output_dir"]
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "state.json").write_text(
            json.dumps(
                {
                    "status": "running",
                    "phase": "verification_filtering",
                    "counters": {"raw_candidates": 3},
                    "artifacts": {},
                    "error": None,
                }
            ),
            encoding="utf-8",
        )
        raise RuntimeError("verification failed")

    monkeypatch.setattr("donzo.cli.run_recon_pipeline", fail_pipeline)

    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "fast",
            "-o",
            str(out_dir),
            "--execute",
            "--no-progress",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    state = json.loads((out_dir / "state.json").read_text(encoding="utf-8"))
    run_error = json.loads((out_dir / "run-error.json").read_text(encoding="utf-8"))

    assert code == 3
    assert result["result"]["error"] == "run_failed"
    assert result["result"]["exception_type"] == "RuntimeError"
    assert state["status"] == "failed"
    assert state["phase"] == "verification_filtering"
    assert state["error"] == "RuntimeError: verification failed"
    assert run_error["exception_type"] == "RuntimeError"
    assert "verification failed" in (out_dir / "run-error.txt").read_text(encoding="utf-8")


def test_cli_run_normal_dry_run_writes_archive_plan(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "normal"
    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "normal",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["result"]["execute"] is False
    assert result["result"]["tool_preflight"]["profile"] == "normal"
    plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in plan["plans"]] == [
        "subfinder",
        "dnsx",
        "httpx",
        "gau",
        "waybackurls",
        "katana",
    ]
    assert all(item["dry_run"] is True for item in plan["plans"])
    assert (out_dir / "tool-preflight.json").exists()
    assert plan["tool_preflight"]["tool_count"] == 6
    state = json.loads((out_dir / "state.json").read_text(encoding="utf-8"))
    assert state["counters"]["planned_commands"] == 6


def test_cli_run_deep_dry_run_writes_deep_plan(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "deep"
    code = main(
        [
            "run",
            "-c",
            "scope.example.yaml",
            "-p",
            "deep",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["result"]["execute"] is False
    assert result["result"]["tool_preflight"]["profile"] == "deep"
    plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in plan["plans"]] == [
        "subfinder",
        "alterx",
        "amass",
        "bbot",
        "uncover",
        "dnsx",
        "tlsx",
        "httpx",
        "gau",
        "waybackurls",
        "waymore",
        "katana",
        "paramspider",
        "qsreplace",
        "arjun",
        "gitleaks",
        "trufflehog",
    ]
    assert all(item["dry_run"] is True for item in plan["plans"])
    preflight_by_name = {item["name"]: item for item in plan["tool_preflight"]["tools"]}
    assert preflight_by_name["amass"]["required_for_run"] is False
    assert preflight_by_name["alterx"]["required_for_run"] is False
    assert preflight_by_name["tlsx"]["required_for_run"] is False
    assert preflight_by_name["bbot"]["required_for_run"] is False
    assert preflight_by_name["paramspider"]["required_for_run"] is False
    assert preflight_by_name["gitleaks"]["required_for_run"] is False
    state = json.loads((out_dir / "state.json").read_text(encoding="utf-8"))
    assert state["counters"]["planned_commands"] == 17


def test_deep_preflight_skips_environment_incompatible_optional_tools(
    tmp_path: Path,
    monkeypatch,
) -> None:
    for name in (
        "SHODAN_API_KEY",
        "SHODAN_KEY",
        "CENSYS_API_TOKEN",
        "CENSYS_ORGANIZATION_ID",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "FOFA_EMAIL",
        "FOFA_KEY",
        "HUNTER_API_KEY",
        "ZOOMEYE_API_KEY",
        "NETLAS_API_KEY",
        "CRIMINALIP_API_KEY",
        "PUBLICWWW_API_KEY",
        "HUNTERHOW_API_KEY",
        "QUAKE_TOKEN",
        "BINARYEDGE_API_KEY",
        "ONYPHE_API_KEY",
        "DRIFTNET_API_KEY",
        "DAYDAYMAP_API_KEY",
        "NERDYDATA_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_API_CX",
        "DONZO_FORCE_BBOT",
        "DONZO_ENABLE_AMASS_PASSIVE",
        "DONZO_ENABLE_ARJUN_PASSIVE",
    ):
        monkeypatch.delenv(name, raising=False)
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )

    preflight = build_tool_preflight(plans, profile="deep")
    skipped = optional_skipped_tools(preflight)

    assert skipped["uncover"] == "missing_provider_keys:uncover"
    assert "amass" not in skipped
    assert skipped["arjun"] == "policy_blocked:blocked_test_type:parameter_fuzzing"
    arjun = next(item for item in plans if item.name == "arjun")
    assert (
        optional_runtime_skip_reason(
            arjun,
            required_for_run=False,
        )
        == "policy_blocked:blocked_test_type:parameter_fuzzing"
    )
    if os.name == "nt":
        assert skipped["bbot"] == "unsupported_on_windows:bbot_dependency_requires_fcntl"


def test_uncover_accepts_current_censys_provider_env_names(monkeypatch) -> None:
    for name in (
        "SHODAN_API_KEY",
        "SHODAN_KEY",
        "CENSYS_API_TOKEN",
        "CENSYS_ORGANIZATION_ID",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "FOFA_EMAIL",
        "FOFA_KEY",
        "HUNTER_API_KEY",
        "ZOOMEYE_API_KEY",
        "NETLAS_API_KEY",
        "CRIMINALIP_API_KEY",
        "PUBLICWWW_API_KEY",
        "HUNTERHOW_API_KEY",
        "QUAKE_TOKEN",
        "BINARYEDGE_API_KEY",
        "ONYPHE_API_KEY",
        "DRIFTNET_API_KEY",
        "DAYDAYMAP_API_KEY",
        "NERDYDATA_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_API_CX",
    ):
        monkeypatch.delenv(name, raising=False)

    assert uncover_provider_keys_present() is False
    assert uncover_configured_engines() == []

    monkeypatch.setenv("CENSYS_ORGANIZATION_ID", "test-org")
    assert uncover_provider_keys_present() is False
    assert uncover_configured_engines() == []

    monkeypatch.setenv("CENSYS_API_TOKEN", "test-token")

    assert uncover_provider_keys_present() is True
    assert uncover_configured_engines() == ["censys"]

    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan")
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    assert uncover_configured_engines() == ["shodan", "censys"]

    monkeypatch.setenv("FOFA_KEY", "test-fofa")
    assert uncover_configured_engines() == ["shodan", "censys", "fofa"]


def test_uncover_plan_selects_configured_engines(
    tmp_path: Path,
    monkeypatch,
) -> None:
    for name in (
        "SHODAN_API_KEY",
        "SHODAN_KEY",
        "CENSYS_API_TOKEN",
        "CENSYS_ORGANIZATION_ID",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "FOFA_EMAIL",
        "FOFA_KEY",
        "HUNTER_API_KEY",
        "ZOOMEYE_API_KEY",
        "NETLAS_API_KEY",
        "CRIMINALIP_API_KEY",
        "PUBLICWWW_API_KEY",
        "HUNTERHOW_API_KEY",
        "QUAKE_TOKEN",
        "BINARYEDGE_API_KEY",
        "ONYPHE_API_KEY",
        "DRIFTNET_API_KEY",
        "DAYDAYMAP_API_KEY",
        "NERDYDATA_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_API_CX",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan")
    monkeypatch.setenv("CENSYS_API_TOKEN", "test-token")
    monkeypatch.setenv("CENSYS_ORGANIZATION_ID", "test-org")
    monkeypatch.setenv("FOFA_EMAIL", "test@example.com")
    monkeypatch.setenv("FOFA_KEY", "test-fofa")

    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )

    uncover_plan = next(item for item in plans if item.name == "uncover")

    assert "-e" in uncover_plan.argv
    assert uncover_plan.argv[uncover_plan.argv.index("-e") + 1] == "shodan,censys,fofa"


def test_httpx_plan_enables_passive_fingerprinting(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )

    httpx_plan = next(item for item in plans if item.name == "httpx")

    for flag in ("-title", "-server", "-td", "-favicon", "-jarm", "-tls-grab"):
        assert flag in httpx_plan.argv


def test_optional_command_failures_are_reported_as_skips() -> None:
    result = normalize_optional_command_failure(
        {"error": "timeout", "returncode": None},
        required_for_run=False,
    )

    assert result["error"] is None
    assert result["skipped"] is True
    assert result["skip_reason"] == "optional_tool_failed:timeout"


def test_optional_alterx_skips_empty_subfinder_input(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    input_path = tmp_path / "subfinder.txt"
    input_path.write_text("\n", encoding="utf-8")
    plan = build_command_plan(
        config=config,
        name="alterx",
        argv=["alterx", "-l", str(input_path), "-silent"],
        output_path=tmp_path / "alterx.txt",
        targets=["example.com"],
        dry_run=False,
    )

    assert optional_runtime_skip_reason(plan, required_for_run=False) == "empty_input:subfinder"
    assert optional_runtime_skip_reason(plan, required_for_run=True) == ""


def test_deep_alterx_plan_uses_stdin_input(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )
    alterx = next(item for item in plans if item.name == "alterx")

    assert Path(alterx.argv[0]).name in {"alterx", "alterx.exe"}
    assert alterx.argv[1:] == ["-l", "stdin", "-silent"]
    assert alterx.stdin_path == tmp_path / "deep" / "raw" / "subfinder.txt"


def test_deep_bbot_plan_uses_single_dependency_mode(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )
    bbot = next(item for item in plans if item.name == "bbot")

    assert "--no-deps" in bbot.argv
    assert "--ignore-failed-deps" not in bbot.argv


def test_bbot_core_dependency_gap_skips_before_sudo_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DONZO_FORCE_BBOT_CORE_DEPS", raising=False)
    monkeypatch.delenv("BBOT_SUDO_PASS", raising=False)
    monkeypatch.setattr("donzo.pipeline.shutil.which", lambda binary: None)
    monkeypatch.setattr("donzo.pipeline.openssl_dev_headers_present", lambda: False)

    reason = bbot_core_dependency_skip_reason()

    assert reason == "missing_bbot_core_deps:unzip,zipinfo,7z,openssl_dev_headers"


def test_bbot_core_dependency_gap_can_be_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DONZO_FORCE_BBOT_CORE_DEPS", "1")
    monkeypatch.delenv("BBOT_SUDO_PASS", raising=False)
    monkeypatch.setattr("donzo.pipeline.shutil.which", lambda binary: None)
    monkeypatch.setattr("donzo.pipeline.openssl_dev_headers_present", lambda: False)

    assert bbot_core_dependency_skip_reason() == ""


def test_deep_arjun_plan_is_blocked_by_parameter_fuzzing_policy(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )
    arjun = next(item for item in plans if item.name == "arjun")

    assert arjun.allowed is False
    assert "blocked_test_type:parameter_fuzzing" in arjun.reasons
    assert (
        optional_runtime_skip_reason(
            arjun,
            required_for_run=False,
        )
        == "policy_blocked:blocked_test_type:parameter_fuzzing"
    )


def test_required_command_partial_stdout_is_not_reported_as_failure(tmp_path: Path) -> None:
    output_path = tmp_path / "httpx.jsonl"
    output_path.write_text('{"url":"https://app.example.com"}\n', encoding="utf-8")

    result = normalize_optional_command_failure(
        {"error": "timeout", "returncode": None, "stdout_path": str(output_path)},
        required_for_run=True,
    )

    assert result["error"] is None
    assert result["partial_output"] is True
    assert result["warning"] == "partial_output_from_timeout"


def test_optional_command_timeout_is_shorter_than_required_timeout() -> None:
    config = load_scope_config(Path("scope.example.yaml"))

    assert command_timeout_seconds("amass", config=config, required_for_run=False) < (
        command_timeout_seconds("dnsx", config=config, required_for_run=True)
    )


def test_normal_recon_plan_uses_current_katana_jsonl_flag(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "normal",
        profile="normal",
    )
    katana = next(item for item in plans if item.name == "katana")
    assert "-jsonl" in katana.argv
    assert "-json" not in katana.argv


def test_recon_plan_applies_scope_rate_limits_to_supported_tools(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "normal",
        profile="normal",
    )
    by_name = {plan.name: plan.argv for plan in plans}

    assert_flag_value(by_name["subfinder"], "-rl", "3")
    assert_flag_value(by_name["subfinder"], "-timeout", "10")
    assert_flag_value(by_name["dnsx"], "-t", "5")
    assert_flag_value(by_name["dnsx"], "-rl", "3")
    assert_flag_value(by_name["dnsx"], "-timeout", "10s")
    assert_flag_value(by_name["httpx"], "-t", "5")
    assert_flag_value(by_name["httpx"], "-rl", "3")
    assert_flag_value(by_name["httpx"], "-timeout", "10")
    assert_flag_value(by_name["katana"], "-c", "5")
    assert_flag_value(by_name["katana"], "-p", "1")
    assert_flag_value(by_name["katana"], "-rl", "3")
    assert_flag_value(by_name["katana"], "-timeout", "10")
    assert_flag_value(by_name["katana"], "-depth", "1")
    assert_flag_value(by_name["katana"], "-ct", "10s")
    assert_flag_value(by_name["katana"], "-mdp", "10")
    assert "-iqp" in by_name["katana"]
    assert "-fsu" in by_name["katana"]
    assert "-ob" in by_name["katana"]
    assert "-or" in by_name["katana"]
    assert_flag_value(by_name["gau"], "--threads", "5")
    assert_flag_value(by_name["gau"], "--timeout", "10")


def test_long_recon_env_raises_bounded_normal_katana_and_command_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    monkeypatch.setenv("DONZO_LONG_RECON", "1")
    monkeypatch.setenv("DONZO_KATANA_DEPTH", "3")
    monkeypatch.setenv("DONZO_KATANA_CRAWL_DURATION", "60")
    monkeypatch.setenv("DONZO_KATANA_MAX_DOMAIN_PAGES", "70")
    monkeypatch.setenv("DONZO_COMMAND_TIMEOUT_AMASS", "240")

    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "normal",
        profile="normal",
    )
    by_name = {plan.name: plan.argv for plan in plans}

    assert_flag_value(by_name["katana"], "-depth", "3")
    assert_flag_value(by_name["katana"], "-ct", "60s")
    assert_flag_value(by_name["katana"], "-mdp", "70")
    assert command_timeout_seconds("amass", config=config, required_for_run=False) == 240
    assert command_timeout_seconds("katana", config=config, required_for_run=True) >= 90


def test_deep_profile_omits_depth_and_timeout_options_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    monkeypatch.delenv("DONZO_USE_TOOL_DEFAULT_LIMITS", raising=False)

    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "deep",
        profile="deep",
    )
    by_name = {plan.name: plan.argv for plan in plans}

    assert "-timeout" not in by_name["subfinder"]
    assert "-timeout" not in by_name["dnsx"]
    assert "-timeout" not in by_name["httpx"]
    assert "--timeout" not in by_name["gau"]
    assert "-depth" not in by_name["katana"]
    assert "-timeout" not in by_name["katana"]
    assert "-ct" not in by_name["katana"]
    assert "-mdp" not in by_name["katana"]
    assert (
        command_timeout_seconds(
            "katana",
            profile="deep",
            config=config,
            required_for_run=True,
        )
        is None
    )


def test_tool_default_limits_env_omits_normal_depth_and_timeout_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    monkeypatch.setenv("DONZO_USE_TOOL_DEFAULT_LIMITS", "1")

    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path / "normal",
        profile="normal",
    )
    by_name = {plan.name: plan.argv for plan in plans}

    assert "-timeout" not in by_name["subfinder"]
    assert "-timeout" not in by_name["dnsx"]
    assert "-timeout" not in by_name["httpx"]
    assert "--timeout" not in by_name["gau"]
    assert "-depth" not in by_name["katana"]
    assert "-timeout" not in by_name["katana"]
    assert "-ct" not in by_name["katana"]
    assert "-mdp" not in by_name["katana"]
    assert command_timeout_seconds("katana", config=config, required_for_run=True) is None


def test_deep_run_starts_independent_asset_collectors_in_parallel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    derived_dir.mkdir()
    plan = [
        build_command_plan(
            config=config,
            name="subfinder",
            argv=["subfinder"],
            output_path=raw_dir / "subfinder.txt",
            targets=["example.com"],
            dry_run=False,
        ),
        build_command_plan(
            config=config,
            name="amass",
            argv=["amass"],
            output_path=raw_dir / "amass.txt",
            targets=["example.com"],
            dry_run=False,
        ),
        build_command_plan(
            config=config,
            name="dnsx",
            argv=["dnsx"],
            output_path=raw_dir / "dnsx.txt",
            targets=["example.com"],
            dry_run=False,
        ),
        build_command_plan(
            config=config,
            name="httpx",
            argv=["httpx"],
            output_path=raw_dir / "httpx.jsonl",
            targets=["example.com"],
            dry_run=False,
        ),
    ]
    events: list[tuple[str, str, float]] = []
    lock = threading.Lock()

    def fake_run_command_plan(
        plan,
        *,
        execute: bool = False,
        timeout_seconds: float | None = 60,
        timeout_error: str = "timeout",
    ) -> CommandResult:
        with lock:
            events.append(("start", plan.name, time.monotonic()))
        if plan.name == "subfinder":
            time.sleep(0.05)
            stdout = "app.example.com\n"
        elif plan.name == "dnsx":
            stdout = "app.example.com\n"
        elif plan.name == "httpx":
            stdout = '{"url":"https://app.example.com","status_code":200}\n'
        else:
            stdout = ""
        plan.output_path.parent.mkdir(parents=True, exist_ok=True)
        plan.output_path.write_text(stdout, encoding="utf-8")
        stderr_path = plan.output_path.with_suffix(plan.output_path.suffix + ".stderr")
        stderr_path.write_text("", encoding="utf-8")
        with lock:
            events.append(("finish", plan.name, time.monotonic()))
        return CommandResult(
            plan=plan,
            returncode=0,
            stdout_path=str(plan.output_path),
            stderr_path=str(stderr_path),
            error=None,
        )

    monkeypatch.setattr("donzo.pipeline.run_command_plan", fake_run_command_plan)

    results = run_deep_recon_commands_parallel(
        plan=plan,
        config=config,
        raw_dir=raw_dir,
        derived_dir=derived_dir,
        optional_skips={},
        required_by_name={item.name: True for item in plan},
        progress_callback=None,
    )

    event_times = {(kind, name): timestamp for kind, name, timestamp in events}
    event_order = [(kind, name) for kind, name, _timestamp in events]
    assert [item["plan"]["name"] for item in results] == ["subfinder", "amass", "dnsx", "httpx"]
    assert event_times[("start", "amass")] < event_times[("finish", "subfinder")]
    assert event_order.index(("finish", "dnsx")) < event_order.index(("start", "httpx"))


def test_httpx_uses_resolved_probe_asset_file(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    output_dir = tmp_path / "normal"
    plans = build_recon_command_plans(
        config=config,
        output_dir=output_dir,
        profile="normal",
    )
    httpx = next(item for item in plans if item.name == "httpx")

    assert_flag_value(httpx.argv, "-l", str(output_dir / "derived" / "http_probe_assets.txt"))


def assert_flag_value(argv: list[str], flag: str, value: str) -> None:
    index = argv.index(flag)
    assert argv[index + 1] == value


def test_load_tool_json_records_skips_invalid_lines(tmp_path: Path) -> None:
    path = tmp_path / "tool.jsonl"
    path.write_text(
        '{"url":"https://api.example.com"}\nflag provided but not defined: -json\n[]\n',
        encoding="utf-8",
    )
    records, removed = load_tool_json_records(path, "katana")
    assert records == [{"url": "https://api.example.com"}]
    assert [item["reason"] for item in removed] == [
        "invalid_json:Expecting value",
        "invalid_json:not_object",
    ]


def test_load_tool_json_document_records_accepts_json_arrays(tmp_path: Path) -> None:
    path = tmp_path / "gitleaks.json"
    path.write_text(
        '[{"File":"derived/live_urls.txt","RuleID":"generic-api-key"}]',
        encoding="utf-8",
    )
    records, removed = load_tool_json_document_records(path, "gitleaks")

    assert removed == []
    assert records == [{"File": "derived/live_urls.txt", "RuleID": "generic-api-key"}]


def test_runner_can_feed_stdin_file_to_local_tool(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    stdin_path = tmp_path / "input.txt"
    output_path = tmp_path / "output.txt"
    stdin_path.write_text("donzo\n", encoding="utf-8")
    plan = build_command_plan(
        config=config,
        name="local-python",
        argv=[sys.executable, "-c", "import sys; print(sys.stdin.read().upper(), end='')"],
        output_path=output_path,
        targets=["example.com"],
        stdin_path=stdin_path,
        dry_run=False,
    )

    result = run_command_plan(plan, execute=True)

    assert result.returncode == 0
    assert output_path.read_text(encoding="utf-8") == "DONZO\n"


def test_runner_timeout_writes_artifact_paths(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    output_path = tmp_path / "timeout.txt"
    plan = build_command_plan(
        config=config,
        name="local-python-timeout",
        argv=[
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(30)",
        ],
        output_path=output_path,
        targets=["example.com"],
        dry_run=False,
    )

    result = run_command_plan(plan, execute=True, timeout_seconds=0.2)

    assert result.error == "timeout"
    assert result.stdout_path == str(output_path)
    assert result.stderr_path == str(output_path.with_suffix(".txt.stderr"))
    assert "started" in output_path.read_text(encoding="utf-8")


def test_runner_can_label_timeout_as_tool_hung(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    output_path = tmp_path / "hung.txt"
    plan = build_command_plan(
        config=config,
        name="local-python-hung",
        argv=[
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(30)",
        ],
        output_path=output_path,
        targets=["example.com"],
        dry_run=False,
    )

    result = run_command_plan(
        plan,
        execute=True,
        timeout_seconds=0.2,
        timeout_error="tool_hung",
    )

    assert result.error == "tool_hung"
    assert result.stdout_path == str(output_path)
    assert "started" in output_path.read_text(encoding="utf-8")


def test_bbot_uses_hang_guard_even_in_deep_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    monkeypatch.delenv("DONZO_BBOT_HANG_GUARD_SECONDS", raising=False)

    assert (
        command_timeout_seconds(
            "bbot",
            profile="deep",
            config=config,
            required_for_run=False,
        )
        == 900.0
    )
    assert command_timeout_error("bbot") == "tool_hung"
    assert (
        command_timeout_seconds(
            "katana",
            profile="deep",
            config=config,
            required_for_run=True,
        )
        is None
    )


def test_bbot_hang_guard_can_be_disabled_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    monkeypatch.setenv("DONZO_BBOT_HANG_GUARD_SECONDS", "0")

    assert (
        command_timeout_seconds(
            "bbot",
            profile="deep",
            config=config,
            required_for_run=False,
        )
        is None
    )


def test_deep_intermediate_files_are_scope_filtered(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    (raw_dir / "subfinder.txt").write_text(
        "api.example.com\npayments.example.com\n",
        encoding="utf-8",
    )
    (raw_dir / "waymore.txt").write_text(
        "https://api.example.com/v1/users?id=1\nhttps://payments.example.com/checkout\n",
        encoding="utf-8",
    )

    write_candidate_assets_file(config=config, raw_dir=raw_dir, derived_dir=derived_dir)
    write_archive_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    assert (derived_dir / "candidate_assets.txt").read_text(encoding="utf-8").splitlines() == [
        "example.com",
        "api.example.com",
    ]
    assert (derived_dir / "archive_urls.txt").read_text(encoding="utf-8").splitlines() == [
        "https://api.example.com/v1/users?id=1"
    ]


def test_http_probe_asset_inputs_prefer_dnsx_results(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    derived_dir.mkdir()
    (derived_dir / "candidate_assets.txt").write_text(
        "example.com\napi.example.com\nadmin.example.com\n",
        encoding="utf-8",
    )
    (raw_dir / "dnsx.txt").write_text("api.example.com\n", encoding="utf-8")

    write_http_probe_asset_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    assert (derived_dir / "http_probe_assets.txt").read_text(encoding="utf-8").splitlines() == [
        "app.example.com",
        "example.com",
        "api.example.com",
    ]


def test_http_probe_asset_inputs_fall_back_to_candidate_assets(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    derived_dir.mkdir()
    (derived_dir / "candidate_assets.txt").write_text(
        "api.example.com\nout.example.net\n",
        encoding="utf-8",
    )

    write_http_probe_asset_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    assert (derived_dir / "http_probe_assets.txt").read_text(encoding="utf-8").splitlines() == [
        "app.example.com",
        "example.com",
        "api.example.com",
    ]


def test_live_url_inputs_survive_missing_httpx_and_seed_scope_urls(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    derived_dir.mkdir()
    (derived_dir / "archive_urls.txt").write_text(
        "\n".join(
            [
                "https://api.example.com/v1/users?id=1",
                "https://app.example.com/assets/app.js",
                "https://app.example.com/assets/font.ttf",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    urls = (derived_dir / "live_urls.txt").read_text(encoding="utf-8").splitlines()
    assert urls[0] == "https://app.example.com"
    assert "https://app.example.com/lms" in urls
    assert "https://api.example.com" in urls
    assert "https://api.example.com/v1/users?id=1" in urls


def test_api_surface_candidates_include_lms_and_api_roots() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    endpoints, removed = api_surface_candidates(
        [{"url": "https://app.example.com", "method": "GET"}],
        config=config,
    )

    urls = {str(item.get("url") or "") for item in endpoints}
    assert removed == []
    assert "https://app.example.com/lms" in urls
    assert "https://app.example.com/lms/api" in urls
    assert "https://app.example.com/graphql" in urls


def test_robots_sitemap_and_collection_extract_api_endpoints() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    robots_endpoints, sitemap_urls, removed = endpoints_from_robots_text(
        """
        User-agent: *
        Allow: /lms
        Disallow: /admin/private
        Sitemap: https://app.example.com/sitemap.xml
        """,
        base_url="https://app.example.com",
        config=config,
    )
    robot_urls = {str(item.get("url") or "") for item in robots_endpoints}
    assert removed == []
    assert "https://app.example.com/lms" in robot_urls
    assert "https://app.example.com/admin/private" in robot_urls
    assert sitemap_urls == ["https://app.example.com/sitemap.xml"]

    sitemap_endpoints, sitemap_removed = endpoints_from_sitemap_text(
        """
        <urlset>
          <url><loc>https://app.example.com/lms/api/courses</loc></url>
          <url><loc>https://payments.example.com/private</loc></url>
        </urlset>
        """,
        config=config,
    )
    sitemap_endpoint_urls = {str(item.get("url") or "") for item in sitemap_endpoints}
    assert "https://app.example.com/lms/api/courses" in sitemap_endpoint_urls
    assert sitemap_removed

    collection = json.loads(
        Path("harness/fixtures/sample-artifacts/postman-collection.json").read_text(
            encoding="utf-8"
        )
    )
    collection_endpoints, collection_removed = endpoints_from_api_collection_document(
        collection,
        base_url="",
        config=config,
    )
    collection_urls = {str(item.get("url") or "") for item in collection_endpoints}
    assert collection_removed == []
    assert "https://api.example.com/lms/api/courses?student_id=1" in collection_urls
    assert "https://api.example.com/graphql" in collection_urls


def test_authenticated_katana_header_is_redacted_in_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    config = replace(
        config,
        authenticated_crawl=AuthenticatedCrawlConfig(
            enabled=True,
            header_env="DONZO_TEST_AUTH_HEADER",
        ),
    )
    monkeypatch.setenv("DONZO_TEST_AUTH_HEADER", "Authorization: Bearer secret-token")

    plans = build_recon_command_plans(
        config=config,
        output_dir=tmp_path,
        profile="normal",
        dry_run=True,
    )
    katana = next(item for item in plans if item.name == "katana")

    assert "Authorization: Bearer secret-token" in katana.argv
    plan_dict = katana.to_dict()
    assert "Authorization: Bearer secret-token" not in json.dumps(plan_dict)
    assert "Authorization: [REDACTED]" in json.dumps(plan_dict)


def test_llm_empty_triage_and_dashboard_artifacts(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    llm_payload = run_llm_triage_artifacts(
        [],
        config=config,
        output_dir=tmp_path,
        driver_name="auto",
        limit=5,
        allow_external_llm=False,
    )
    assert llm_payload["summary"]["status"] == "empty"
    assert (tmp_path / "llm-triage-summary.json").exists()

    (tmp_path / "verification-summary.json").write_text(
        json.dumps({"filter_reason_counts": {"not_actual_api_doc": 2}}),
        encoding="utf-8",
    )
    (tmp_path / "review-summary.json").write_text(
        json.dumps({"status": "needs_review"}),
        encoding="utf-8",
    )
    write_jsonl(
        tmp_path / "api-semantic-map.jsonl",
        [
            {
                "url": "https://app.example.com/api/courses/{courseId}/members",
                "method": "GET",
                "resource": "course",
                "action": "read",
                "auth_guess": "member_or_owner",
                "risk_weight": 50,
            }
        ],
    )
    dashboard = write_dashboard_artifacts(
        tmp_path,
        payload={
            "profile": "normal",
            "assets": 1,
            "services": 0,
            "endpoints": 3,
            "api_docs": 0,
            "graphql_endpoints": 0,
            "source_maps": 0,
            "candidates": 0,
            "reviewable_candidates": 0,
            "filtered_candidates": 0,
            "clusters": 0,
        },
        config=config,
    )
    assert Path(dashboard["dashboard_html"]).exists()
    assert Path(dashboard["dashboard_json"]).exists()
    dashboard_json = json.loads(Path(dashboard["dashboard_json"]).read_text(encoding="utf-8"))
    assert dashboard_json["counts"]["api_semantics"] == 1
    assert dashboard_json["api_semantic_context"][0]["resource"] == "course"


def test_llm_triage_limit_zero_submits_all_packs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    submitted_pack_ids: list[str] = []

    class FakeTriageResult:
        def __init__(self, pack_id: str) -> None:
            self.pack_id = pack_id

        def to_dict(self) -> dict[str, Any]:
            return {
                "stage": "cluster_triage",
                "llm_status": "succeeded",
                "input_count": 1,
                "submitted_count": 1,
                "output": {"pack_id": self.pack_id},
            }

    def fake_run_cluster_triage(pack: dict[str, Any], **_kwargs: Any) -> FakeTriageResult:
        pack_id = str(pack["pack_id"])
        submitted_pack_ids.append(pack_id)
        return FakeTriageResult(pack_id)

    monkeypatch.setattr("donzo.pipeline.run_cluster_triage", fake_run_cluster_triage)

    llm_payload = run_llm_triage_artifacts(
        [
            {"pack_id": "pack-1", "cluster_id": "cluster-1"},
            {"pack_id": "pack-2", "cluster_id": "cluster-2"},
            {"pack_id": "pack-3", "cluster_id": "cluster-3"},
        ],
        config=config,
        output_dir=tmp_path,
        driver_name="auto",
        limit=0,
        allow_external_llm=True,
    )

    assert submitted_pack_ids == ["pack-1", "pack-2", "pack-3"]
    assert llm_payload["summary"]["submitted_count"] == 3
    assert llm_payload["summary"]["llm_calls_requested"] == 3


def test_llm_triage_input_packs_include_filtered_raw_recheck() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_candidates = [
        {
            "candidate_id": "raw-api-doc",
            "candidate_type": "EXPOSED_API_DOCS",
            "target": "https://app.example.com/openapi.json",
            "severity": "medium",
            "priority": "P2",
            "risk_score": 61,
            "auto_exploit": False,
        }
    ]
    filtered_candidates = [
        {
            **raw_candidates[0],
            "verification_status": "filtered_out",
            "filter_reason": "not_actual_api_doc",
        }
    ]

    packs = build_llm_triage_input_packs(
        [],
        raw_candidates=raw_candidates,
        reviewable_candidates=[],
        filtered_candidates=filtered_candidates,
        config=config,
    )

    assert len(packs) == 1
    pack = packs[0]
    assert pack["pack_kind"] == "filtered_candidate_recheck"
    assert pack["triage_source"] == "candidates-filtered.jsonl"
    assert pack["candidate_context"]["raw_candidates"] == 1
    assert pack["candidate_context"]["filtered_candidates"] == 1
    assert pack["safety_constraints"]["automatic_exploit"] is False
    assert "false-negative risk" in pack["task"]


def test_llm_triage_input_packs_include_technology_context() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    packs = build_llm_triage_input_packs(
        [],
        raw_candidates=[],
        reviewable_candidates=[],
        filtered_candidates=[],
        technology_inferences=[
            {
                "inference_id": "tech-1",
                "origin": "https://app.example.com",
                "host": "app.example.com",
                "confidence": 0.8,
                "technologies": [{"name": "spring_boot", "category": "backend_framework"}],
                "api_hints": [{"hint": "/api", "count": 3}],
                "evidence": ["service.tech:Spring Boot"],
            }
        ],
        config=config,
    )

    assert len(packs) == 1
    assert packs[0]["pack_kind"] == "technology_inference_context"
    assert packs[0]["triage_source"] == "technology-inference.jsonl"
    assert packs[0]["cluster"]["representative_target"] == "https://app.example.com"
    assert packs[0]["technology_inference"]["technologies"][0]["name"] == "spring_boot"


def test_llm_triage_input_packs_include_api_semantic_context() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    packs = build_llm_triage_input_packs(
        [],
        raw_candidates=[],
        reviewable_candidates=[],
        filtered_candidates=[],
        api_semantic_map=[
            {
                "semantic_id": "semantic-1",
                "url": "https://app.example.com/api/courses/{courseId}/members",
                "method": "GET",
                "resource": "course",
                "action": "read",
                "auth_guess": "member_or_owner",
                "object_id_params": ["courseid"],
                "risk_weight": 50,
                "risk_questions": ["Are membership/relationship checks enforced server-side?"],
            }
        ],
        config=config,
    )

    assert len(packs) == 1
    assert packs[0]["pack_kind"] == "api_semantic_context"
    assert packs[0]["triage_source"] == "api-semantic-map.jsonl"
    assert packs[0]["cluster"]["representative_target"].endswith("/members")
    assert packs[0]["api_semantic"]["resource"] == "course"
    assert "workflow" in packs[0]["task"] or "authorization" in packs[0]["task"]


def test_review_triage_queue_prefers_llm_input_packs(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    pack = {
        "stage": "cluster_triage",
        "pack_id": "filtered-pack",
        "pack_kind": "filtered_candidate_recheck",
        "cluster": {
            "cluster_id": "cluster-filtered",
            "priority": "P3",
            "targets": ["https://app.example.com/openapi.json"],
        },
        "candidate_count": 1,
    }
    write_jsonl(run_dir / "llm-triage-input-packs.jsonl", [pack])
    write_jsonl(run_dir / "cluster-evidence-packs.jsonl", [])
    (run_dir / "llm-triage-input-packs").mkdir(parents=True)
    (run_dir / "llm-triage-input-packs" / "filtered-pack.json").write_text(
        json.dumps(pack),
        encoding="utf-8",
    )
    (run_dir / "recon-result.json").write_text(
        json.dumps({"scope_file": "scope.example.yaml"}),
        encoding="utf-8",
    )

    queue = build_llm_triage_queue(run_dir)

    assert queue["status"] == "ready"
    assert queue["queue_count"] == 1
    assert "llm-triage-input-packs" in queue["queue"][0]["input"]


def test_run_diff_reports_only_new_records(tmp_path: Path) -> None:
    previous = tmp_path / "previous"
    current = tmp_path / "current"
    write_jsonl(
        previous / "endpoints.jsonl",
        [{"url": "https://app.example.com", "method": "GET"}],
    )
    write_jsonl(
        current / "endpoints.jsonl",
        [
            {"url": "https://app.example.com", "method": "GET"},
            {"url": "https://app.example.com/lms", "method": "GET"},
        ],
    )
    write_jsonl(previous / "candidates-verified.jsonl", [])
    write_jsonl(
        current / "candidates-verified.jsonl",
        [{"candidate_type": "GRAPHQL", "target": "https://app.example.com/graphql"}],
    )
    write_jsonl(previous / "findings.jsonl", [])
    write_jsonl(current / "findings.jsonl", [])

    diff = build_run_diff(previous, current)

    assert diff["summary"]["new_endpoints"] == 1
    assert diff["summary"]["new_candidates"] == 1
    assert (current / "run-diff.json").exists()
    assert (current / "run-diff.md").exists()


def test_live_url_inputs_are_capped_after_seed_urls(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    raw_dir = tmp_path / "raw"
    derived_dir = tmp_path / "derived"
    raw_dir.mkdir()
    derived_dir.mkdir()
    archive_urls = [f"https://app.example.com/api/{index}" for index in range(80)]
    (derived_dir / "archive_urls.txt").write_text(
        "\n".join(archive_urls) + "\n",
        encoding="utf-8",
    )

    write_live_url_inputs(config=config, raw_dir=raw_dir, derived_dir=derived_dir)

    urls = (derived_dir / "live_urls.txt").read_text(encoding="utf-8").splitlines()
    assert len(urls) == 30
    assert urls[0] == "https://app.example.com"


def test_scope_seed_urls_keep_configured_path_bases() -> None:
    config = load_scope_config(Path("scope.example.yaml"))

    assert scope_seed_urls(config) == ["https://app.example.com"]


def test_secret_scan_records_are_redacted_manual_review_findings() -> None:
    records = [
        {
            "File": "derived/live_urls.txt",
            "RuleID": "generic-api-key",
            "Secret": "sk-abcdefghijklmnopqrstuvwxyz",
            "Match": "token=sk-abcdefghijklmnopqrstuvwxyz",
        }
    ]

    findings, removed = normalize_secret_scan_records(records, source="gitleaks")

    assert removed == []
    assert findings[0]["candidate_type"] == "SECRET_EXPOSURE"
    assert findings[0]["verification_status"] == "needs_manual_review"
    assert findings[0]["auto_exploit"] is False
    evidence_record = findings[0]["evidence"]["record"]
    assert evidence_record["Secret"] == "[REDACTED]"
    assert evidence_record["Match"] == "[REDACTED]"


def test_review_commands_summarize_fixture_run(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "review-fixture"
    code = main(
        [
            "run-fixture",
            "-c",
            "scope.example.yaml",
            "-p",
            "normal",
            "--endpoints",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "-o",
            str(out_dir),
        ]
    )
    assert code == 0
    capsys.readouterr()

    code = main(["review", "write", "-r", str(out_dir)])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["written"] is True
    assert (out_dir / "review.md").exists()
    assert (out_dir / "verification-debug.md").exists()
    assert (out_dir / "llm-triage-queue.json").exists()

    code = main(["review", "summary", "-r", str(out_dir), "--include-filtered"])
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert code == 0
    assert summary["summary"]["status"] in {
        "manual_review_required",
        "empty_after_verification",
    }
    assert "reviewable_candidates" in summary["summary"]["counts"]

    code = main(["review", "debug", "-r", str(out_dir), "--limit", "1"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Verification Debug" in captured.out


def test_check_tools_unknown_name_is_ignored() -> None:
    assert check_tools(["definitely-not-a-donzo-tool"]) == []


def test_load_project_dotenv_reads_local_file_without_overwriting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DONZO_AUTH_COOKIE", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.setenv("DONZO_EXISTING", "from-shell")
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "# comment",
                'DONZO_AUTH_COOKIE="token=fixture"',
                "export SHODAN_API_KEY=fixture-shodan",
                "DONZO_EXISTING=from-file",
                "not an env line",
            ]
        ),
        encoding="utf-8",
    )

    loaded = load_project_dotenv([tmp_path / ".env"])

    assert loaded == [tmp_path / ".env"]
    assert os.environ["DONZO_AUTH_COOKIE"] == "token=fixture"
    assert os.environ["SHODAN_API_KEY"] == "fixture-shodan"
    assert os.environ["DONZO_EXISTING"] == "from-shell"


def test_tool_matrix_reports_required_and_optional_tools() -> None:
    matrix = tool_matrix()
    assert matrix["profiles"]["fast"]["required"] == ["subfinder", "dnsx", "httpx", "katana"]
    assert {"gau", "waybackurls"}.issubset(matrix["profiles"]["normal"]["required"])
    assert "naabu" in matrix["profiles"]["normal"]["optional"]
    assert matrix["profiles"]["deep"]["required"] == [
        "subfinder",
        "dnsx",
        "httpx",
        "katana",
        "gau",
        "waybackurls",
    ]
    assert {"amass", "paramspider", "kiterunner"}.issubset(matrix["profiles"]["deep"]["optional"])


def test_cli_tools_matrix(capsys) -> None:
    code = main(["tools", "matrix"])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["profiles"]["normal"]["optional"] == ["naabu", "nuclei"]
    assert "deep" in result["profiles"]


def test_run_progress_renderer_outputs_numbered_bars() -> None:
    stream = StringIO()
    renderer = RunProgressRenderer(stream=stream, in_place=False)
    renderer(
        {
            "event": "plan_ready",
            "plans": [
                {"name": "subfinder", "allowed": True},
                {"name": "dnsx", "allowed": True},
            ],
        }
    )
    renderer({"event": "command_started", "name": "subfinder"})
    renderer({"event": "command_finished", "name": "subfinder", "error": None})
    output = stream.getvalue()
    assert "1. subfinder [##------------------] ... 10% running" in output
    assert "2. dnsx [--------------------] ... 0% pending" in output
    assert "1. subfinder [####################] ... 100% done" in output


def test_run_progress_renderer_marks_missing_optional_tool_skipped() -> None:
    stream = StringIO()
    renderer = RunProgressRenderer(stream=stream, in_place=False)
    renderer(
        {
            "event": "plan_ready",
            "pipeline_steps": [
                {"name": "scope / preflight", "status": "done", "percent": 100},
                {"name": "recon commands", "status": "pending", "percent": 0},
            ],
            "plans": [
                {"name": "amass", "allowed": True},
            ],
        }
    )
    renderer({"event": "command_started", "name": "amass", "index": 1, "total": 1})
    renderer(
        {
            "event": "command_finished",
            "name": "amass",
            "index": 1,
            "total": 1,
            "error": "optional_tool_missing",
        }
    )
    output = stream.getvalue()
    assert "1. amass [--------------------] ... 0% skipped" in output
    assert "error:optional_tool_missing" not in output


def test_run_progress_renderer_outputs_pipeline_steps() -> None:
    stream = StringIO()
    renderer = RunProgressRenderer(stream=stream, in_place=False)
    renderer(
        {
            "event": "plan_ready",
            "pipeline_steps": [
                {"name": "scope / preflight", "status": "done", "percent": 100},
                {"name": "recon commands", "status": "pending", "percent": 0},
                {"name": "verification / filtering", "status": "pending", "percent": 0},
            ],
            "plans": [
                {"name": "subfinder", "allowed": True},
                {"name": "dnsx", "allowed": True},
            ],
        }
    )
    renderer({"event": "command_finished", "name": "subfinder", "index": 1, "total": 2})
    renderer({"event": "pipeline_step_started", "name": "verification / filtering"})
    renderer(
        {
            "event": "verification_progress",
            "processed": 25,
            "total": 100,
            "probe_used": 7,
            "probe_limit": 50,
            "origin_timeout_cached": 2,
            "percent": 25,
        }
    )
    output = stream.getvalue()
    assert "Pipeline" in output
    assert "Tools" in output
    assert "1. scope / preflight [####################] ... 100% done" in output
    assert "2. recon commands [##########----------] ... 50% running" in output
    assert (
        "3. verification / filtering [#####---------------] ... 25% "
        "running 25/100 candidates, probes 7/50, cached 2"
    ) in output


def test_run_progress_renderer_can_update_in_place() -> None:
    stream = StringIO()
    renderer = RunProgressRenderer(stream=stream, in_place=True)
    renderer(
        {
            "event": "plan_ready",
            "plans": [
                {"name": "subfinder", "allowed": True},
                {"name": "dnsx", "allowed": True},
            ],
        }
    )
    renderer({"event": "command_started", "name": "subfinder"})
    output = stream.getvalue()
    assert "\x1b[3F" in output
    assert "\x1b[2K1. subfinder [##------------------] ... 10% running" in output


def test_cli_tools_install_without_execute_only_prints_plan(capsys) -> None:
    code = main(["tools", "install", "subfinder"])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["execute"] is False
    assert result["plans"][0]["argv"][1] == "install"


def test_cli_doctor_reports_policy_tools_and_codex(monkeypatch, capsys) -> None:
    class FakeCodexDriver:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def preflight(self) -> SimpleNamespace:
            return SimpleNamespace(command="codex", version="codex-cli test", doctor="ok")

    def fake_check_tools(names: list[str]) -> list[dict[str, object]]:
        return [
            {
                "name": name,
                "binary": name,
                "path": f"/fake/{name}",
                "available": True,
                "required_for_fast": True,
                "version": "test",
                "error": None,
            }
            for name in names
        ]

    monkeypatch.setattr("donzo.cli.CodexCliDriver", FakeCodexDriver)
    monkeypatch.setattr("donzo.cli.check_tools", fake_check_tools)
    code = main(["doctor", "-c", "scope.example.yaml"])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["ok"] is True
    assert result["policy"]["valid"] is True
    assert result["tools"]["ok"] is True
    assert result["codex_cli"]["ok"] is True


def test_cli_normalize_and_report_render(tmp_path: Path, capsys) -> None:
    assets_path = tmp_path / "assets.jsonl"
    code = main(
        [
            "normalize",
            "-c",
            "scope.example.yaml",
            "--kind",
            "asset",
            "-i",
            "harness/fixtures/sample-artifacts/subdomains.txt",
            "-o",
            str(assets_path),
        ]
    )
    assert code == 0
    capsys.readouterr()
    assets = load_json_records(assets_path)
    assert [item["asset"] for item in assets] == ["app.example.com", "api.example.com"]

    endpoints_path = tmp_path / "endpoints.jsonl"
    report_path = tmp_path / "report.md"
    code = main(
        [
            "normalize",
            "-c",
            "scope.example.yaml",
            "--kind",
            "endpoint",
            "-i",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "-o",
            str(endpoints_path),
        ]
    )
    assert code == 0
    capsys.readouterr()
    assert endpoints_path.exists()

    candidates_path = tmp_path / "candidates.jsonl"
    code = main(
        [
            "candidates",
            "build",
            "-c",
            "scope.example.yaml",
            "-i",
            str(endpoints_path),
            "-o",
            str(candidates_path),
        ]
    )
    assert code == 0
    capsys.readouterr()

    ranked_path = tmp_path / "ranked.jsonl"
    code = main(["rank", "-i", str(candidates_path), "-o", str(ranked_path)])
    assert code == 0
    capsys.readouterr()

    code = main(
        [
            "report",
            "render",
            "-c",
            "scope.example.yaml",
            "-i",
            str(ranked_path),
            "-o",
            str(report_path),
        ]
    )
    assert code == 0
    assert report_path.exists()


def test_cli_analyze_js_and_openapi_write_outputs(tmp_path: Path, capsys) -> None:
    js_endpoints_path = tmp_path / "js-endpoints.jsonl"
    js_candidates_path = tmp_path / "js-candidates.jsonl"
    code = main(
        [
            "analyze",
            "js",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/app.js",
            "--base-url",
            "https://app.example.com",
            "-o",
            str(js_endpoints_path),
            "--candidates-output",
            str(js_candidates_path),
        ]
    )
    assert code == 0
    capsys.readouterr()
    assert js_endpoints_path.exists()
    assert js_candidates_path.exists()

    openapi_endpoints_path = tmp_path / "openapi-endpoints.jsonl"
    openapi_candidates_path = tmp_path / "openapi-candidates.jsonl"
    code = main(
        [
            "analyze",
            "openapi",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/openapi.json",
            "--base-url",
            "https://api.example.com",
            "-o",
            str(openapi_endpoints_path),
            "--candidates-output",
            str(openapi_candidates_path),
        ]
    )
    assert code == 0
    assert openapi_endpoints_path.exists()
    assert openapi_candidates_path.exists()


def test_cli_ingest_har_writes_model_artifacts(tmp_path: Path, capsys) -> None:
    traffic_path = tmp_path / "traffic.jsonl"
    api_endpoints_path = tmp_path / "api-endpoints.jsonl"
    schema_diff_path = tmp_path / "schema-diff.jsonl"

    code = main(
        [
            "ingest-har",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/traffic.har",
            "--actor",
            "user_A",
            "--state",
            "logged_in",
            "-o",
            str(traffic_path),
            "--api-endpoints-output",
            str(api_endpoints_path),
            "--schema-diff-output",
            str(schema_diff_path),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert code == 0
    assert result["traffic_count"] == 3
    assert result["api_endpoint_model_count"] >= 2
    assert traffic_path.exists()
    assert api_endpoints_path.exists()
    assert schema_diff_path.exists()


def test_run_fixture_with_har_writes_phase_0_2_artifacts(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "har-fixture"
    code = main(
        [
            "run-fixture",
            "-c",
            "scope.example.yaml",
            "-p",
            "normal",
            "--endpoints",
            "harness/fixtures/sample-artifacts/endpoints.json",
            "--har",
            "harness/fixtures/sample-artifacts/traffic.har",
            "--traffic-actor",
            "user_A",
            "--traffic-state",
            "logged_in",
            "-o",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert code == 0
    assert result["traffic_count"] == 3
    assert result["request_schema_count"] == 1
    assert result["response_schema_count"] == 3
    assert result["api_endpoint_model_count"] >= 3
    assert result["schema_diff_count"] >= 1
    assert result["security_invariant_count"] >= 1
    assert result["safe_manual_test_plan_count"] >= 1
    assert result["oracle_template_count"] >= 1
    assert (out_dir / "traffic.jsonl").exists()
    assert (out_dir / "api-endpoints.jsonl").exists()
    assert (out_dir / "parameter-classification.jsonl").exists()
    assert (out_dir / "schema-diff.jsonl").exists()
    assert (out_dir / "api-dependency-graph.json").exists()
    assert (out_dir / "handler-hypotheses.jsonl").exists()
    assert (out_dir / "security-invariants.jsonl").exists()
    assert (out_dir / "manual-test-plans.jsonl").exists()
    assert (out_dir / "oracle-templates.jsonl").exists()
