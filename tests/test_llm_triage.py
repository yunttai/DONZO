from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from donzo.cli import main
from donzo.config import load_scope_config
from donzo.llm_triage.drivers.codex_cli import build_codex_exec_args, build_job_paths
from donzo.llm_triage.evidence_pack import build_evidence_pack
from donzo.llm_triage.tribunal import run_tribunal, should_triage_with_llm


def test_mandatory_llm_fails_closed_without_external_call() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    finding = {
        "title": "Public Swagger UI",
        "severity": "medium",
        "target": "https://api.example.com/swagger-ui/",
        "candidate_type": "EXPOSED_API_DOCS",
        "source": ["fixture"],
        "status_code": 200,
        "evidence": {"response_path": "response.txt"},
    }
    result = run_tribunal(finding, config=config, llm_config=config.llm)
    data = result.to_dict()
    assert data["llm_required"] is True
    assert data["fail_closed"] is True
    assert data["driver"] == "codex_cli"
    assert data["llm_status"] == "failed"
    assert data["verification_status"] == "llm_failed"
    assert data["include_in_final_report"] is False
    assert data["verdict"] is None


def test_mandatory_llm_result_matches_schema() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    finding = json.loads(
        Path("harness/fixtures/sample-artifacts/swagger-finding.json").read_text(encoding="utf-8")
    )
    result = run_tribunal(finding, config=config, llm_config=config.llm)
    schema = json.loads(
        Path("harness/schemas/llm-tribunal-result.schema.json").read_text(encoding="utf-8")
    )
    errors = list(Draft202012Validator(schema).iter_errors(result.to_dict()))
    assert errors == []


def test_evidence_pack_redacts_secret_like_values() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    pack = build_evidence_pack(
        config,
        {
            "title": "Secret Candidate",
            "severity": "high",
            "target": "https://api.example.com/app.js",
            "candidate_type": "SECRET_EXPOSURE",
            "response_excerpt": "const token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890';",
            "evidence": {
                "Authorization": "Bearer real-token-value",
                "source_path": "output/raw/app.js",
            },
        },
    ).to_dict()
    serialized = json.dumps(pack)
    assert "ghp_" not in serialized
    assert "real-token-value" not in serialized
    assert "github_token_like" in pack["redactions_applied"]
    assert "header:Authorization" in pack["redactions_applied"]


def test_low_value_finding_is_not_selected_for_tribunal() -> None:
    finding = {
        "title": "Missing X-Frame-Options",
        "severity": "low",
        "target": "https://app.example.com",
        "candidate_type": "MISSING_SECURITY_HEADER",
    }
    assert should_triage_with_llm(finding) is False


def test_out_of_scope_tribunal_verdict() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    finding = {
        "title": "Public Swagger UI",
        "severity": "medium",
        "target": "https://payments.example.com/swagger-ui/",
        "candidate_type": "EXPOSED_API_DOCS",
        "source": ["fixture"],
    }
    result = run_tribunal(
        finding,
        config=config,
        llm_config=config.llm,
        target_allowed=False,
    )
    assert result.llm_status == "not_submitted"
    assert result.verification_status == "out_of_scope_or_not_allowed"
    assert result.include_in_final_report is False


def test_cli_tribunal_run_marks_llm_failed_without_external_call(capsys) -> None:
    code = main(
        [
            "tribunal",
            "run",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/swagger-finding.json",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 3
    assert result["triaged"] is True
    assert result["result"]["driver"] == "codex_cli"
    assert result["result"]["llm_status"] == "failed"
    assert result["result"]["include_in_final_report"] is False


def test_codex_cli_driver_builds_schema_constrained_exec_args() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    paths = build_job_paths("artifacts/llm-test", "abc123")
    args = build_codex_exec_args("codex", paths, config.llm.drivers["codex_cli"])
    assert args[:2] == ["codex", "exec"]
    assert "--json" in args
    assert "--output-schema" in args
    assert str(paths.schema_path) in args
    assert "--output-last-message" in args
    assert str(paths.verdict_path) in args
    assert "--sandbox" in args
    assert "read-only" in args
    assert "--ignore-user-config" in args
    assert "--ignore-rules" in args
    assert "--strict-config" in args
    assert "--model" in args
    assert "gpt-5.5" in args
    assert "--config" in args
    assert 'model_reasoning_effort="xhigh"' in args
    assert args[-1] == "-"


def test_cli_candidate_generation_marks_llm_failed_without_external_call(capsys) -> None:
    code = main(
        [
            "candidates",
            "generate",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/endpoints.json",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 3
    assert result["generated"] is False
    assert result["result"]["stage"] == "candidate_generator"
    assert result["result"]["driver"] == "codex_cli"
    assert result["result"]["llm_status"] == "failed"
    assert result["result"]["submitted_count"] == 1


def test_cli_cluster_triage_marks_llm_failed_without_external_call(
    tmp_path: Path,
    capsys,
) -> None:
    pack_path = tmp_path / "cluster-pack.json"
    pack_path.write_text(
        json.dumps(
            {
                "stage": "cluster_triage",
                "program": "example-bounty",
                "cluster": {
                    "cluster_id": "cluster-1",
                    "cluster_type": "API_DOCS",
                    "targets": ["https://api.example.com/swagger-ui/"],
                },
                "evidence_summary": {
                    "verified_count": 1,
                    "representative_target": "https://api.example.com/swagger-ui/",
                },
                "safety_constraints": {
                    "automatic_exploit": False,
                    "destructive_testing": False,
                    "secret_validation": False,
                },
            }
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "clusters",
            "triage",
            "-c",
            "scope.example.yaml",
            "-i",
            str(pack_path),
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 3
    assert result["triaged"] is False
    assert result["result"]["stage"] == "cluster_triage"
    assert result["result"]["driver"] == "codex_cli"
    assert result["result"]["llm_status"] == "failed"


def test_cli_report_draft_marks_llm_failed_without_external_call(capsys) -> None:
    code = main(
        [
            "report",
            "draft",
            "-c",
            "scope.example.yaml",
            "-i",
            "harness/fixtures/sample-artifacts/findings.raw.json",
        ]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 3
    assert result["drafted"] is False
    assert result["result"]["stage"] == "report_writer"
    assert result["result"]["driver"] == "codex_cli"
    assert result["result"]["llm_status"] == "failed"
    assert result["result"]["submitted_count"] == 2
