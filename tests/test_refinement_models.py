from __future__ import annotations

import json
from pathlib import Path

from donzo.actors import build_actor_model
from donzo.analyzers.business_logic import (
    build_business_flow_models,
    build_business_mutation_plans,
    build_business_state_invariants,
)
from donzo.analyzers.feedback_graph import build_feedback_graph
from donzo.analyzers.graphql_model import (
    build_graphql_logical_endpoint_models,
    build_graphql_operation_models,
    build_graphql_parameter_classifications,
)
from donzo.analyzers.realtime_model import build_sse_event_models, build_websocket_message_models
from donzo.capture.har_wizard import (
    build_flow_manifest_record,
    redact_har_document,
    write_har_capture_artifacts,
)
from donzo.cli import main
from donzo.config import load_scope_config
from donzo.llm_triage.agent_interfaces import (
    build_agent_interfaces,
    build_deterministic_agent_runs,
    validate_agent_run,
)
from donzo.storage.jsonl import load_json_records, write_jsonl
from donzo.traffic.har_ingest import ingest_har_file

GQL_INVITE_MEMBER = (
    "mutation InviteMember($orgId: ID!, $email: String!) { "
    "inviteMember(orgId: $orgId, email: $email) { id email } "
    "}"
)


def test_actor_model_uses_safe_credential_refs_and_relationships() -> None:
    model = build_actor_model(
        [
            {
                "actor_id": "user_A",
                "role": "member",
                "tenant": "org_1",
                "owned_resources": ["course:1"],
                "credential_ref": "env:DONZO_USER_A_COOKIE",
                "relationship_to": {"user_B": "separate_test_account"},
            },
            {
                "actor_id": "user_B",
                "role": "member",
                "tenant": "org_2",
                "token": "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaa.bbbbbbbbbb",
                "credential_ref": "raw-secret-value",
            },
        ]
    )

    by_id = {item["actor_id"]: item for item in model["actors"]}
    assert by_id["user_A"]["credential_ref"] == "env:DONZO_USER_A_COOKIE"
    assert by_id["user_B"]["credential_ref"] == "[REDACTED]"
    assert model["owned_resources"][0]["safe_fixture_only"] is True
    assert any(item["relationship"] == "separate_test_account" for item in model["relationships"])
    assert any(item["warning"] == "raw_credential_field_redacted" for item in model["warnings"])


def test_har_ingest_preserves_flow_metadata(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    har_path = tmp_path / "traffic.har"
    har_path.write_text(json.dumps(graphql_har_document()), encoding="utf-8")

    traffic, request_schemas, _response_schemas, removed = ingest_har_file(
        har_path,
        config=config,
        actor="user_A",
        role="member",
        tenant="org_1",
        state="logged_in",
        flow="invite_member",
        label="create_invite",
    )

    assert not removed
    assert traffic[0]["role"] == "member"
    assert traffic[0]["tenant"] == "org_1"
    assert traffic[0]["flow"] == "invite_member"
    assert request_schemas[0]["label"] == "create_invite"


def test_graphql_operations_are_logical_endpoints() -> None:
    traffic = [
        {
            "traffic_id": "traffic-1",
            "actor": "user_A",
            "role": "member",
            "tenant": "org_1",
            "request": {
                "method": "POST",
                "url": "https://app.example.com/graphql",
                "body_sample_redacted": {
                    "operationName": "InviteMember",
                    "query": GQL_INVITE_MEMBER,
                    "variables": {"orgId": "org_1", "email": "[EMAIL]"},
                },
            },
            "response": {"status": 200},
        }
    ]

    operations = build_graphql_operation_models(traffic)
    logical = build_graphql_logical_endpoint_models(operations)
    classifications = build_graphql_parameter_classifications(operations)

    assert operations[0]["operation_name"] == "InviteMember"
    assert operations[0]["operation_type"] == "mutation"
    assert "orgId" in operations[0]["variable_names"]
    assert logical[0]["endpoint_id"].endswith("#InviteMember")
    assert classifications[0]["parameters"][0]["location"] == "body"


def test_business_logic_generates_manual_mutation_plans() -> None:
    endpoints = [
        {
            "endpoint_id": "POST https://app.example.com/api/invitations",
            "path_template": "/api/invitations",
            "resource": "invitation",
            "action": "invite",
            "risk_tags": ["TOKEN_REPLAY"],
        }
    ]
    flows = build_business_flow_models(endpoints)
    invariants = build_business_state_invariants(flows)
    plans = build_business_mutation_plans(flows)

    assert flows[0]["flow_type"] == "invitation"
    assert {item["type"] for item in invariants} >= {"token_lifetime", "state_transition"}
    assert {item["strategy"] for item in plans} >= {
        "repeat",
        "accept-after-revoke",
        "reuse-expired-token",
    }
    assert all(item["auto_execute"] is False for item in plans)


def test_feedback_graph_updates_oracle_confidence() -> None:
    graph, updates = build_feedback_graph(
        [
            {"test_id": "test-1", "endpoint_id": "endpoint-1", "status": 403},
            {
                "test_id": "test-2",
                "endpoint_id": "endpoint-2",
                "status": 200,
                "body": {"token": "raw-token-value"},
            },
        ],
        dependency_graph={
            "edges": [
                {"edge_id": "edge-1", "from": "endpoint-1", "to": "endpoint-2"},
            ]
        },
        state_transitions=[
            {
                "transition_id": "transition-1",
                "from_endpoint": "endpoint-1",
                "to_endpoint": "endpoint-2",
            }
        ],
    )

    assert graph["summary"]["secure_denials"] == 1
    assert graph["summary"]["unexpected_successes"] == 1
    assert len(graph["edges"]) == 2
    assert {item["feedback_bucket"] for item in updates} == {"secure_denial", "unexpected_success"}


def test_realtime_models_websocket_and_sse() -> None:
    ws_messages, ws_logical, ws_removed = build_websocket_message_models(
        [
            {
                "connection_url": "wss://app.example.com/socket",
                "message_type": "room.join",
                "payload": {"roomId": "room_1", "orgId": "org_1"},
                "headers": {"Authorization": "Bearer secret"},
            }
        ]
    )
    sse_events, sse_logical, sse_removed = build_sse_event_models(
        [
            {
                "stream_url": "https://app.example.com/events",
                "event_name": "member.updated",
                "data": {"userId": "user_1", "tenantId": "org_1"},
            }
        ]
    )

    assert not ws_removed and not sse_removed
    assert ws_messages[0]["auth_handshake"]["headers"]["authorization"] == "[REDACTED]"
    assert "TENANT_ISOLATION" in ws_logical[0]["risk_tags"]
    assert sse_events[0]["stream_scope"] == "tenant_scoped"
    assert sse_logical[0]["protocol"] == "sse"


def test_har_capture_artifacts_are_redacted(tmp_path: Path) -> None:
    config = load_scope_config(Path("scope.example.yaml"))
    har_path = tmp_path / "raw.har"
    har_path.write_text(
        json.dumps(graphql_har_document(auth_header="Bearer raw-secret-token")), encoding="utf-8"
    )

    redacted = redact_har_document(json.loads(har_path.read_text(encoding="utf-8")))
    assert "raw-secret-token" not in json.dumps(redacted)

    result = write_har_capture_artifacts(
        har_path=har_path,
        output_dir=tmp_path / "capture",
        config=config,
        target="https://app.example.com/graphql",
        actor="user_A",
        role="member",
        tenant="org_1",
        state="logged_in",
        flow="invite_member",
        label="create_invite",
    )
    assert result["captured"] is True
    assert (tmp_path / "capture" / "flow-manifest.jsonl").exists()
    assert "raw-secret-token" not in (tmp_path / "capture" / "traffic.har").read_text(
        encoding="utf-8"
    )
    manifest = build_flow_manifest_record(
        target="https://app.example.com/graphql",
        actor="user_A",
        role="member",
    )
    assert manifest["redacted"] is True


def test_agent_interfaces_and_deterministic_runs_validate() -> None:
    interfaces = build_agent_interfaces()
    runs = build_deterministic_agent_runs(
        api_endpoint_models=[{"endpoint_id": "endpoint-1"}],
        security_invariants=[{"invariant_id": "invariant-1"}],
    )

    assert len(interfaces["agent_interfaces"]) == 8
    assert all(validate_agent_run(item)["valid"] for item in runs)
    assert all(item["external_llm_called"] is False for item in runs)


def test_cli_refinement_artifacts_from_fixture(tmp_path: Path, capsys) -> None:
    actor_path = tmp_path / "actors.jsonl"
    har_path = tmp_path / "graphql.har"
    out_dir = tmp_path / "out"
    write_jsonl(
        actor_path,
        [
            {
                "actor_id": "user_A",
                "role": "member",
                "tenant": "org_1",
                "credential_ref": "env:DONZO_USER_A_COOKIE",
            },
            {
                "actor_id": "user_B",
                "role": "member",
                "tenant": "org_2",
                "credential_ref": "env:DONZO_USER_B_COOKIE",
            },
        ],
    )
    har_path.write_text(json.dumps(graphql_har_document()), encoding="utf-8")

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
            str(har_path),
            "--actors",
            str(actor_path),
            "--traffic-actor",
            "user_A",
            "--traffic-role",
            "member",
            "--traffic-tenant",
            "org_1",
            "--traffic-flow",
            "invite_member",
            "--traffic-label",
            "create_invite",
            "-o",
            str(out_dir),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert result["actor_count"] == 2
    assert result["graphql_operation_count"] == 1
    assert result["business_flow_count"] >= 1
    assert result["agent_run_count"] >= 1
    assert load_json_records(out_dir / "manual-test-plans.jsonl")[0]["actor_context"]
    assert (out_dir / "agent-interfaces.json").exists()


def graphql_har_document(auth_header: str = "Bearer [REDACTED]") -> dict[str, object]:
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://app.example.com/graphql",
                        "headers": [
                            {"name": "Authorization", "value": auth_header},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "operationName": "InviteMember",
                                    "query": GQL_INVITE_MEMBER,
                                    "variables": {"orgId": "org_1", "email": "member@example.com"},
                                }
                            ),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "data": {
                                        "inviteMember": {
                                            "id": "inv_1",
                                            "email": "member@example.com",
                                        }
                                    }
                                }
                            ),
                        },
                    },
                }
            ]
        }
    }
