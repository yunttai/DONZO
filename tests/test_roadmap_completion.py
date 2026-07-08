from __future__ import annotations

import json
from pathlib import Path

from donzo.analyzers.field_semantics import classify_fields
from donzo.cli import main
from donzo.llm_triage.agent_outputs import (
    build_agent_output_scaffolds,
    validate_agent_output,
)
from donzo.oracles.oracle_evaluator import evaluate_oracle_results
from donzo.reporting.regression_case import build_regression_cases
from donzo.reporting.report_draft import build_report_drafts
from donzo.storage.jsonl import load_json_records, write_jsonl


def test_field_semantics_classifies_privilege_and_filename_fields() -> None:
    records = classify_fields(
        [
            {"name": "isAdmin", "location": "body", "endpoint_id": "endpoint-1"},
            {"name": "avatarFilename", "location": "body", "endpoint_id": "endpoint-1"},
        ]
    )

    by_name = {item["name"]: item for item in records}
    assert by_name["isAdmin"]["semantic_class"] == "privilege_flag"
    assert by_name["avatarFilename"]["semantic_class"] == "filename_field"
    assert "BFLA" in by_name["isAdmin"]["risk_tags"]


def test_oracle_evaluator_report_draft_and_regression_cases() -> None:
    test_plans = [
        {
            "test_id": "test-bola",
            "endpoint_id": "endpoint-course",
            "invariant_id": "invariant-ownership",
            "candidate_vulnerability": "BOLA",
            "oracle": {"type": "differential_body_oracle"},
            "manual_steps": ["Compare account A and account B access to seeded course record."],
        },
        {
            "test_id": "test-bola-denied",
            "endpoint_id": "endpoint-course",
            "invariant_id": "invariant-ownership",
            "candidate_vulnerability": "BOLA",
            "oracle": {"type": "differential_body_oracle"},
        },
        {
            "test_id": "test-mass-assignment",
            "endpoint_id": "endpoint-profile",
            "invariant_id": "invariant-field-allowlist",
            "candidate_vulnerability": "MASS_ASSIGNMENT",
            "oracle": {"type": "mass_assignment_oracle"},
        },
    ]
    oracle_templates = [
        {"test_id": "test-bola", "oracle_type": "differential_body_oracle"},
        {"test_id": "test-bola-denied", "oracle_type": "differential_body_oracle"},
        {"test_id": "test-mass-assignment", "oracle_type": "mass_assignment_oracle"},
    ]
    manual_results = [
        {
            "test_id": "test-bola",
            "mutated_status": 200,
            "response_contains_other_user_data": True,
            "evidence_files": ["evidence/bola.md"],
        },
        {
            "test_id": "test-bola-denied",
            "mutated_status": 403,
            "evidence_files": ["evidence/denied.md"],
        },
        {
            "test_id": "test-mass-assignment",
            "persisted_unexpected_fields": ["isAdmin"],
            "read_back_confirmed": True,
            "evidence_files": ["evidence/mass-assignment.md"],
        },
    ]

    results = evaluate_oracle_results(test_plans, oracle_templates, manual_results)
    statuses = {item["test_id"]: item["oracle_verdict"]["status"] for item in results}
    assert statuses == {
        "test-bola": "confirmed",
        "test-bola-denied": "expected_behavior",
        "test-mass-assignment": "confirmed",
    }

    drafts = build_report_drafts(
        results,
        test_plans=test_plans,
        security_invariants=[
            {
                "invariant_id": "invariant-ownership",
                "invariant_type": "object_ownership",
                "description": "Caller can only access owned course records.",
            },
            {
                "invariant_id": "invariant-field-allowlist",
                "invariant_type": "field_allowlist",
                "description": "Client-controlled role fields must not persist.",
            },
        ],
        api_endpoint_models=[
            {
                "endpoint_id": "endpoint-course",
                "method": "GET",
                "path_template": "/api/courses/{courseId}",
            },
            {
                "endpoint_id": "endpoint-profile",
                "method": "PATCH",
                "path_template": "/api/profile",
            },
        ],
    )
    regression_cases = build_regression_cases(results, test_plans=test_plans)

    assert len(drafts) == 2
    assert {item["affected_endpoint"] for item in drafts} == {
        "GET /api/courses/{courseId}",
        "PATCH /api/profile",
    }
    assert len(regression_cases) == 2
    assert all(
        "automatic exploit" not in " ".join(item["action"]).lower() for item in regression_cases
    )


def test_cli_oracle_evaluate_and_report_from_oracle(tmp_path: Path, capsys) -> None:
    plans_path = tmp_path / "plans.jsonl"
    templates_path = tmp_path / "templates.jsonl"
    manual_path = tmp_path / "manual.jsonl"
    oracle_results_path = tmp_path / "oracle-results.jsonl"
    evidence_path = tmp_path / "oracle-evidence.jsonl"
    drafts_path = tmp_path / "report-drafts.jsonl"
    regression_path = tmp_path / "regression.jsonl"
    markdown_path = tmp_path / "report-drafts.md"

    write_jsonl(
        plans_path,
        [
            {
                "test_id": "test-bola",
                "endpoint_id": "endpoint-course",
                "invariant_id": "invariant-ownership",
                "candidate_vulnerability": "BOLA",
                "oracle": {"type": "differential_body_oracle"},
            }
        ],
    )
    write_jsonl(
        templates_path, [{"test_id": "test-bola", "oracle_type": "differential_body_oracle"}]
    )
    write_jsonl(
        manual_path,
        [
            {
                "test_id": "test-bola",
                "mutated_status": 200,
                "response_contains_other_user_data": True,
                "evidence_files": ["evidence/bola.md"],
            }
        ],
    )

    code = main(
        [
            "oracle",
            "evaluate",
            "--test-plans",
            str(plans_path),
            "--oracle-templates",
            str(templates_path),
            "--manual-results",
            str(manual_path),
            "-o",
            str(oracle_results_path),
            "--evidence-output",
            str(evidence_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert result["status_counts"] == {"confirmed": 1}
    assert load_json_records(oracle_results_path)[0]["include_in_report"] is True
    assert load_json_records(evidence_path)

    code = main(
        [
            "report",
            "from-oracle",
            "--oracle-results",
            str(oracle_results_path),
            "--test-plans",
            str(plans_path),
            "--drafts-output",
            str(drafts_path),
            "--regression-output",
            str(regression_path),
            "--markdown-output",
            str(markdown_path),
        ]
    )
    report_result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert report_result["report_draft_count"] == 1
    assert report_result["regression_case_count"] == 1
    assert load_json_records(drafts_path)[0]["title"].startswith("BOLA")
    assert markdown_path.read_text(encoding="utf-8").startswith("# Oracle Report Drafts")


def test_run_fixture_writes_roadmap_artifacts(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "roadmap-fixture"
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
            "-o",
            str(out_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["ui_field_usage_count"] >= 1
    assert result["llm_agent_output_count"] >= 1
    assert (out_dir / "api-artifact-index.json").exists()
    assert (out_dir / "ui-field-usage.jsonl").exists()
    assert (out_dir / "llm-agent-outputs.jsonl").exists()


def test_llm_agent_output_scaffold_validates_records() -> None:
    records = build_agent_output_scaffolds(
        api_endpoint_models=[
            {
                "endpoint_id": "endpoint-1",
                "path_template": "/api/items/{id}",
                "confidence": 0.75,
            }
        ],
        security_invariants=[
            {
                "invariant_id": "invariant-1",
                "invariant_type": "object_ownership",
                "description": "Caller must own item.",
            }
        ],
    )

    assert len(records) == 2
    assert all(validate_agent_output(item)["valid"] for item in records)
