from __future__ import annotations

from typing import Any

from donzo.analyzers.dependency_graph import build_api_sequences, build_state_transitions


def build_sequence_model(
    traffic: list[dict[str, Any]],
    api_endpoint_models: list[dict[str, Any]],
) -> dict[str, Any]:
    sequences = build_api_sequences(traffic, api_endpoint_models)
    transitions = build_state_transitions(sequences)
    return {
        "sequences": sequences,
        "state_transitions": transitions,
        "summary": {
            "sequence_count": len(sequences),
            "state_transition_count": len(transitions),
            "observed_step_count": sum(len(item.get("steps") or []) for item in sequences),
        },
    }
