from __future__ import annotations

from typing import Any

from donzo.analyzers.feedback_graph import interpretation_for_bucket, status_bucket
from donzo.models import stable_id


def build_fuzz_feedback_graph(records: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for record in records:
        fuzz_id = str(record.get("fuzz_id") or "")
        endpoint_id = str(record.get("endpoint_id") or "unknown")
        bucket = status_bucket(record.get("status") or record.get("status_code"))
        node = nodes.setdefault(
            fuzz_id or endpoint_id,
            {
                "node_id": fuzz_id or endpoint_id,
                "fuzz_id": fuzz_id,
                "endpoint_id": endpoint_id,
                "status_buckets": {},
                "precondition_hints": [],
            },
        )
        node["status_buckets"][bucket] = node["status_buckets"].get(bucket, 0) + 1
        node["precondition_hints"].append(interpretation_for_bucket(bucket))
        if record.get("read_back_for"):
            edges.append(
                {
                    "edge_id": stable_id(
                        "fuzz_readback_edge", record.get("read_back_for"), fuzz_id
                    ),
                    "source": record.get("read_back_for"),
                    "target": fuzz_id,
                    "edge_type": "state_read_back_feedback",
                }
            )
    return {
        "feedback_graph_id": stable_id("fuzz_feedback_graph", sorted(nodes)),
        "nodes": list(nodes.values()),
        "edges": edges,
        "summary": {
            "feedback_count": len(records),
            "fuzz_count": len(nodes),
            "edge_count": len(edges),
            "manual_review_required": True,
        },
    }
