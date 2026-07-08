from __future__ import annotations

from typing import Any

from donzo.oracles.verdict import coerce_bool, oracle_verdict


def evaluate_file_upload_storage_rendering(
    records: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if any(
        coerce_bool(item.get("malware_upload") or item.get("destructive_payload"))
        for item in records
    ):
        return oracle_verdict("blocked_by_safety_policy", 1.0, "unsafe upload payloads are blocked")
    if any(
        coerce_bool(item.get("stored_in_public_location"))
        or coerce_bool(item.get("rendered_as_active_content"))
        or coerce_bool(item.get("access_control_violation"))
        for item in records
    ):
        return oracle_verdict(
            "confirmed",
            0.82,
            "benign upload proof shows unsafe storage, rendering, or access-control behavior",
            "medium",
            evidence=["upload succeeded", "unsafe storage/render/read-back observed"],
        )
    if any(coerce_bool(item.get("upload_succeeded")) for item in records):
        return oracle_verdict(
            "needs_more_evidence",
            0.42,
            "upload success alone is not a vulnerability",
            needs_more_evidence=[
                "storage location, rendering behavior, or access-control read-back"
            ],
        )
    return oracle_verdict("needs_more_evidence", 0.3, "no upload behavior was observed")
