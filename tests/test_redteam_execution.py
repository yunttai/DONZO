from __future__ import annotations

import json
from pathlib import Path

import yaml

from donzo.cli import main
from donzo.redteam.actor_sessions import load_actor_session_manager
from donzo.redteam.executor import RedteamHTTPExecutor
from donzo.redteam.scope_guard import load_redteam_scope_guard
from donzo.storage.jsonl import load_json_records, write_jsonl


def write_redteam_scope(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "engagement": {
                    "name": "unit-redteam",
                    "mode": "redteam",
                    "start_time": "2000-01-01T00:00:00+00:00",
                    "end_time": "2999-12-31T23:59:59+00:00",
                    "operator": "unit-test",
                    "authorization_ref": "ticket-1",
                },
                "scope": {
                    "allowed_hosts": ["api.example.com"],
                    "denied_hosts": ["blocked.example.com"],
                    "allowed_schemes": ["https"],
                    "allowed_paths": ["/api/"],
                    "denied_paths": ["/api/admin-danger"],
                    "allowed_methods": ["GET", "POST"],
                },
                "limits": {
                    "max_rps": 100,
                    "max_concurrent_requests": 1,
                    "max_requests_per_endpoint": 2,
                    "max_total_requests": 4,
                    "stop_on_5xx_rate_percent": 50,
                    "stop_on_429": True,
                },
                "allowed_classes": ["SQLi", "BOLA", "MassAssignment"],
                "requires_explicit_opt_in": ["CommandInjection"],
                "evidence": {"redact_secrets": True, "store_raw_responses": False},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def write_actors(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "actors": [
                    {
                        "id": "user_A",
                        "role": "org_admin",
                        "tenant": "org_1",
                        "session_ref": "vault://sessions/user_A",
                        "owns": {"invoice": ["invoice_1"]},
                    },
                    {
                        "id": "user_B",
                        "role": "user",
                        "tenant": "org_2",
                        "session_ref": "raw-secret-token",
                    },
                ],
                "relationships": [
                    {"subject": "user_B", "object": "invoice_1", "relation": "must_not_access"}
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_redteam_scope_guard_fails_closed_and_blocks_out_of_scope(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.yaml"
    actors_path = tmp_path / "actors.yaml"
    write_redteam_scope(scope_path)
    write_actors(actors_path)

    guard = load_redteam_scope_guard(scope_path, run_dir=tmp_path)
    actors = load_actor_session_manager(actors_path)

    allowed = guard.evaluate_request(
        {
            "method": "GET",
            "url": "https://api.example.com/api/invoices/1",
            "vulnerability_class": "SQLI",
        },
        mode="redteam",
        actors_present=actors.has_actors,
    )
    denied = guard.evaluate_request(
        {
            "method": "GET",
            "url": "https://api.example.com/api/admin-danger/run",
            "vulnerability_class": "SQLI",
        },
        mode="redteam",
        actors_present=actors.has_actors,
    )
    opt_in = guard.evaluate_request(
        {
            "method": "POST",
            "url": "https://api.example.com/api/jobs",
            "vulnerability_class": "CommandInjection",
        },
        mode="redteam",
        actors_present=actors.has_actors,
    )

    assert allowed.allowed is True
    assert denied.allowed is False
    assert "path_denied:/api/admin-danger" in denied.reasons
    assert opt_in.allowed is False
    assert "explicit_opt_in_required:COMMAND_INJECTION" in opt_in.reasons


def test_actor_session_manager_keeps_reference_only_sessions(tmp_path: Path) -> None:
    actors_path = tmp_path / "actors.yaml"
    write_actors(actors_path)

    actors = load_actor_session_manager(actors_path)

    assert actors.actor("user_A").session_ref == "vault://sessions/user_A"
    assert actors.actor("user_B").session_ref == "[REDACTED]"
    assert any("unsafe_reference_redacted" in warning for warning in actors.warnings)


def test_redteam_executor_dry_run_and_mock_execution(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.yaml"
    actors_path = tmp_path / "actors.yaml"
    write_redteam_scope(scope_path)
    write_actors(actors_path)
    guard = load_redteam_scope_guard(scope_path, run_dir=tmp_path)
    actors = load_actor_session_manager(actors_path)
    requests = [
        {
            "method": "GET",
            "url": "https://api.example.com/api/invoices/1",
            "endpoint_id": "GET /api/invoices/{id}",
            "vulnerability_class": "SQLI",
            "probe_role": "baseline",
            "headers": {"Authorization": "Bearer secret-token"},
        }
    ]

    dry_run = RedteamHTTPExecutor(guard, actors).execute_requests(
        requests,
        mode="assisted",
        execute=False,
    )
    assert dry_run["blocked_requests"][0]["status"] == "not_executed"

    executed = RedteamHTTPExecutor(
        guard,
        actors,
        transport=lambda _request: {"status": 200, "headers": {}, "body": {"ok": True}},
    ).execute_requests(requests, mode="assisted", execute=True)

    assert executed["baseline_results"][0]["status"] == 200
    assert (
        executed["evidence"][0]["request"]["headers"]["authorization"]
        == "[REDACTED]"
    )


def test_cli_redteam_init_and_run_writes_artifacts(tmp_path: Path, capsys) -> None:
    scope_path = tmp_path / "scope.yaml"
    actors_path = tmp_path / "actors.yaml"
    run_dir = tmp_path / "run"
    requests_path = tmp_path / "requests.jsonl"
    write_redteam_scope(scope_path)
    write_actors(actors_path)
    write_jsonl(
        requests_path,
        [
            {
                "method": "GET",
                "url": "https://api.example.com/api/invoices/1",
                "endpoint_id": "GET /api/invoices/{id}",
                "vulnerability_class": "SQLI",
            }
        ],
    )

    code = main(
        [
            "redteam",
            "init",
            "--scope",
            str(scope_path),
            "--actors",
            str(actors_path),
            "-o",
            str(run_dir),
        ]
    )
    init_result = json.loads(capsys.readouterr().out)
    assert code == 0
    assert init_result["ready"] is True
    assert (run_dir / "planning" / "probe-plan.jsonl").exists()

    code = main(
        [
            "redteam-run",
            "--run",
            str(run_dir),
            "--requests",
            str(requests_path),
            "--mode",
            "assisted",
        ]
    )
    run_result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert run_result["executed"] is False
    assert load_json_records(run_dir / "execution" / "blocked-requests.jsonl")


def test_cli_redteam_run_execute_requires_redteam_or_lab_mode(tmp_path: Path, capsys) -> None:
    scope_path = tmp_path / "scope.yaml"
    actors_path = tmp_path / "actors.yaml"
    requests_path = tmp_path / "requests.jsonl"
    output_dir = tmp_path / "run"
    write_redteam_scope(scope_path)
    write_actors(actors_path)
    write_jsonl(
        requests_path,
        [
            {
                "method": "GET",
                "url": "https://api.example.com/api/invoices/1",
                "endpoint_id": "GET /api/invoices/{id}",
                "vulnerability_class": "SQLI",
            }
        ],
    )

    code = main(
        [
            "redteam-run",
            "--scope",
            str(scope_path),
            "--actors",
            str(actors_path),
            "--requests",
            str(requests_path),
            "--mode",
            "assisted",
            "--execute",
            "-o",
            str(output_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 2
    assert result["executed"] is False
    assert result["error"] == "execute_requires_redteam_or_lab_mode"
