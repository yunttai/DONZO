from __future__ import annotations

import json
from pathlib import Path

from donzo.cli import main
from donzo.fuzzing import build_fuzz_artifacts
from donzo.fuzzing.response_normalizer import normalized_response_hash
from donzo.fuzzing.safety_policy import evaluate_fuzz_safety
from donzo.oracles.bfla import evaluate_bfla_role_differential
from donzo.oracles.bola import evaluate_bola_cross_actor
from donzo.oracles.business_logic import evaluate_business_logic_sequence_state
from donzo.oracles.ede import evaluate_ede_field_diff
from donzo.oracles.fuzz_engine import evaluate_fuzz_oracle_results
from donzo.oracles.mass_assignment import evaluate_mass_assignment_read_back
from donzo.oracles.sqli import evaluate_sqli_boolean_differential
from donzo.oracles.ssrf import evaluate_ssrf_oast_callback
from donzo.oracles.ssti import evaluate_ssti_server_side_evaluation
from donzo.storage.jsonl import load_json_records, write_jsonl


def test_response_normalization_removes_dynamic_fields() -> None:
    left = {"id": 1, "requestId": "abc", "updatedAt": "2026-07-09T00:00:01Z", "name": "A"}
    right = {"id": 1, "requestId": "def", "updatedAt": "2026-07-09T00:00:02Z", "name": "A"}

    assert normalized_response_hash(left) == normalized_response_hash(right)


def test_fuzz_candidate_plan_probe_artifacts_are_safe() -> None:
    artifacts = build_fuzz_artifacts(
        api_endpoint_models=[
            {
                "endpoint_id": "GET https://api.example.com/orders",
                "method": "GET",
                "path_template": "/orders",
                "query_params": ["filter", "callbackUrl"],
                "risk_tags": ["SINK_REVIEW"],
            },
            {
                "endpoint_id": "post https://api.example.com/templates/upload",
                "method": "post",
                "path_template": "/templates/upload",
                "query_params": ["template"],
                "body_params": ["file"],
            }
        ],
        parameter_classifications=[],
        schema_diffs=[],
    )

    classes = {item["vulnerability_class"] for item in artifacts["fuzz_plan"]}
    assert {"SQLI", "SSRF"} <= classes
    assert {"PATH_TRAVERSAL", "FILE_UPLOAD"} <= classes
    assert all(item["auto_execute"] is False for item in artifacts["safe_probes"])
    assert all(item["destructive"] is False for item in artifacts["safe_probes"])


def test_safety_policy_blocks_live_or_unsafe_actions() -> None:
    safe_plan = {"vulnerability_class": "SQLI", "safety": {"max_requests": 8, "destructive": False}}
    unsafe_plan = {
        "vulnerability_class": "SQLI",
        "safety": {"requested_actions": ["destructive_mutation"]},
    }
    ssrf_plan = {"vulnerability_class": "SSRF", "safety": {"max_requests": 4}}

    assert evaluate_fuzz_safety(safe_plan)["allowed"] is True
    assert evaluate_fuzz_safety(unsafe_plan)["status"] == "blocked_by_safety_policy"
    assert evaluate_fuzz_safety(ssrf_plan)["status"] == "blocked_by_safety_policy"
    live = evaluate_fuzz_safety(safe_plan, mode="live")
    assert "live_requires:explicit_scope" in live["reasons"]


def test_sqli_differential_oracle_confirms_only_isolated_difference() -> None:
    baseline = [
        {"body": {"items": [1], "requestId": "a"}, "status": 200},
        {"body": {"items": [1], "requestId": "b"}, "status": 200},
    ]
    controls = [{"body": {"items": [1], "requestId": "c"}, "probe_role": "control"}]
    probes = [
        {"body": {"items": [1], "requestId": "d"}, "mutation_kind": "true_condition_marker"},
        {"body": {"items": []}, "mutation_kind": "false_condition_marker"},
    ]

    verdict = evaluate_sqli_boolean_differential(baseline, controls, probes)

    assert verdict["status"] == "confirmed"

    unknown_source = evaluate_ssrf_oast_callback(
        [{"oast_token": "token-2", "probe_role": "mutation"}],
        [{"token": "token-2", "protocol": "http"}],
    )

    assert unknown_source["status"] == "false_positive"
    assert verdict["confidence"] >= 0.9


def test_ssrf_oast_oracle_matches_server_side_token() -> None:
    verdict = evaluate_ssrf_oast_callback(
        [{"oast_token": "token-1", "probe_role": "mutation"}],
        [
            {
                "token": "token-1",
                "protocol": "http",
                "source_class": "server_side",
                "browser_loaded": False,
            }
        ],
    )

    assert verdict["status"] == "confirmed"


def test_ssti_oracle_requires_server_side_evaluation_not_reflection() -> None:
    reflected = evaluate_ssti_server_side_evaluation(
        controls=[],
        probes=[{"reflected": True}],
    )
    confirmed = evaluate_ssti_server_side_evaluation(
        controls=[{"evaluated": False}],
        probes=[{"evaluated": True, "raw_response_observed": True}],
    )

    assert reflected["status"] == "needs_more_evidence"
    assert confirmed["status"] == "confirmed"


def test_bola_and_bfla_oracles_use_actor_and_readback_evidence() -> None:
    bola = evaluate_bola_cross_actor(
        [
            {
                "probe_role": "mutation",
                "status": 200,
                "contains_other_actor_data": True,
                "preconditions_satisfied": True,
            }
        ]
    )
    bfla = evaluate_bfla_role_differential(
        [{"probe_role": "mutation", "status": 200, "privileged_action_succeeded": True}],
        {"privileged_actor_can_perform": True, "member_must_not_perform": True},
    )

    assert bola["status"] == "confirmed"
    assert bfla["status"] == "confirmed"


def test_readback_field_and_business_oracles() -> None:
    mass = evaluate_mass_assignment_read_back(
        [{"submitted_field": "isAdmin", "read_back_confirmed": True}]
    )
    ede = evaluate_ede_field_diff(
        [{"response_fields": ["email", "mfaSecret"], "sensitive_unneeded_fields": ["mfaSecret"]}]
    )
    business = evaluate_business_logic_sequence_state(
        [{"invalid_transition_succeeded": True, "read_back_confirmed": True}]
    )

    assert mass["status"] == "confirmed"
    assert ede["status"] == "confirmed"
    assert business["status"] == "confirmed"


def test_fuzz_engine_generates_verdict_findings_and_regression_cases() -> None:
    fuzz_plan = {
        "fuzz_id": "FZ-MASS-1",
        "endpoint_id": "PATCH https://api.example.com/profile",
        "path_template": "/profile",
        "vulnerability_class": "MASS_ASSIGNMENT",
        "oracle": "mass_assignment_read_back_oracle",
        "target_parameter": {"name": "isAdmin", "location": "body"},
        "safety": {"max_requests": 8, "destructive": False},
    }

    artifacts = evaluate_fuzz_oracle_results(
        [fuzz_plan],
        fuzz_results=[
            {
                "fuzz_id": "FZ-MASS-1",
                "probe_role": "mutation",
                "submitted_field": "isAdmin",
                "read_back_confirmed": True,
            }
        ],
    )

    assert artifacts["oracle_verdicts"][0]["verdict"] == "confirmed"
    assert artifacts["confirmed_findings"][0]["auto_exploit"] is False
    assert artifacts["regression_cases"][0]["candidate_vulnerability"] == "MASS_ASSIGNMENT"


def test_fuzz_engine_converts_sqli_and_ssti_confirmations_to_findings() -> None:
    fuzz_plans = [
        {
            "fuzz_id": "FZ-SQLI-1",
            "endpoint_id": "GET https://api.example.com/orders",
            "path_template": "/orders",
            "vulnerability_class": "SQLI",
            "oracle": "sqli_boolean_differential_oracle",
            "target_parameter": {"name": "filter", "location": "query"},
            "safety": {"max_requests": 8, "destructive": False},
        },
        {
            "fuzz_id": "FZ-SSTI-1",
            "endpoint_id": "POST https://api.example.com/templates/preview",
            "path_template": "/templates/preview",
            "vulnerability_class": "SSTI",
            "oracle": "ssti_server_side_expression_evaluation_oracle",
            "target_parameter": {"name": "template", "location": "body"},
            "safety": {"max_requests": 8, "destructive": False},
        },
    ]

    artifacts = evaluate_fuzz_oracle_results(
        fuzz_plans,
        baseline_results=[
            {"fuzz_id": "FZ-SQLI-1", "body": {"items": [1], "requestId": "a"}, "status": 200},
            {"fuzz_id": "FZ-SQLI-1", "body": {"items": [1], "requestId": "b"}, "status": 200},
        ],
        fuzz_results=[
            {
                "fuzz_id": "FZ-SQLI-1",
                "probe_role": "control",
                "body": {"items": [1], "requestId": "c"},
            },
            {
                "fuzz_id": "FZ-SQLI-1",
                "probe_role": "mutation",
                "mutation_kind": "true_condition_marker",
                "body": {"items": [1], "requestId": "d"},
            },
            {
                "fuzz_id": "FZ-SQLI-1",
                "probe_role": "mutation",
                "mutation_kind": "false_condition_marker",
                "body": {"items": []},
            },
            {"fuzz_id": "FZ-SSTI-1", "probe_role": "control", "evaluated": False},
            {
                "fuzz_id": "FZ-SSTI-1",
                "probe_role": "mutation",
                "evaluated": True,
                "raw_response_observed": True,
            },
        ],
    )

    assert {item["candidate_type"] for item in artifacts["confirmed_findings"]} == {
        "SQLI",
        "SSTI",
    }


def test_cli_fuzz_plan_and_evaluate_write_artifacts(tmp_path: Path, capsys) -> None:
    api_path = tmp_path / "api-endpoints.jsonl"
    plan_dir = tmp_path / "plan"
    eval_dir = tmp_path / "eval"
    write_jsonl(
        api_path,
        [
            {
                "endpoint_id": "PATCH https://api.example.com/profile",
                "method": "PATCH",
                "path_template": "/profile",
                "body_params": ["isAdmin"],
            }
        ],
    )

    code = main(
        [
            "fuzz",
            "plan",
            "-c",
            "scope.example.yaml",
            "--api-endpoints",
            str(api_path),
            "-o",
            str(plan_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["fuzz_plan_count"] >= 1
    assert (plan_dir / "planning" / "fuzz-plan.jsonl").exists()
    assert (plan_dir / "planning" / "probe-plan.jsonl").exists()
    plans = load_json_records(plan_dir / "planning" / "fuzz-plan.jsonl")
    mass_plan = next(item for item in plans if item["vulnerability_class"] == "MASS_ASSIGNMENT")
    fuzz_results_path = tmp_path / "fuzz-results.jsonl"
    write_jsonl(
        fuzz_results_path,
        [
            {
                "fuzz_id": mass_plan["fuzz_id"],
                "endpoint_id": mass_plan["endpoint_id"],
                "probe_role": "mutation",
                "submitted_field": "isAdmin",
                "read_back_confirmed": True,
            }
        ],
    )

    code = main(
        [
            "fuzz",
            "evaluate",
            "--fuzz-plan",
            str(plan_dir / "planning" / "fuzz-plan.jsonl"),
            "--fuzz-results",
            str(fuzz_results_path),
            "-o",
            str(eval_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["status_counts"]["confirmed"] >= 1
    assert load_json_records(eval_dir / "reports" / "confirmed-findings.jsonl")
    assert load_json_records(eval_dir / "findings.jsonl")
