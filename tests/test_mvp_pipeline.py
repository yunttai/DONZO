from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from donzo.candidates.basic import build_basic_candidates
from donzo.cli import main
from donzo.config import load_scope_config
from donzo.normalize.artifacts import normalize_asset_lines, normalize_endpoint_records
from donzo.parameters import build_parameters_from_endpoints
from donzo.ranking import rank_records
from donzo.runner import build_command_plan
from donzo.storage.jsonl import load_json_records
from donzo.tools import check_tools


def test_endpoint_normalize_candidate_rank_pipeline() -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    records = load_json_records(Path("harness/fixtures/sample-artifacts/endpoints.json"))
    endpoints, removed = normalize_endpoint_records(records, config=config, source="fixture")
    assert removed == []
    assert endpoints[0]["risk_hints"] == ["object_resource"]

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
    assert (out_dir / "candidates.jsonl").exists()
    assert (out_dir / "findings.jsonl").exists()
    assert (out_dir / "ranked.jsonl").exists()
    assert (out_dir / "recon-result.json").exists()
    assert (out_dir / "report.md").exists()
    assert result["evidence_notes"] == 1
    assert list((out_dir / "evidence").glob("*/notes.md"))
    assert "Bug Bounty Recon Report" in (out_dir / "report.md").read_text(encoding="utf-8")


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
    assert (out_dir / "plan.json").exists()
    plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in plan["plans"]] == ["subfinder", "dnsx", "httpx", "katana"]
    assert all(item["dry_run"] is True for item in plan["plans"])


def test_check_tools_unknown_name_is_ignored() -> None:
    assert check_tools(["definitely-not-a-donzo-tool"]) == []


def test_cli_tools_install_without_execute_only_prints_plan(capsys) -> None:
    code = main(["tools", "install", "subfinder"])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code == 0
    assert result["execute"] is False
    assert result["plans"][0]["argv"][0:2] == ["go", "install"]


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
