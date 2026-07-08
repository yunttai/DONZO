from __future__ import annotations

from statistics import median
from typing import Any

from donzo.fuzzing.response_normalizer import result_hash
from donzo.models import stable_id


def build_baseline_set(
    records: list[dict[str, Any]],
    *,
    fuzz_id: str | None = None,
    endpoint_id: str | None = None,
) -> dict[str, Any]:
    scoped = [
        item
        for item in records
        if (not fuzz_id or not item.get("fuzz_id") or str(item.get("fuzz_id") or "") == fuzz_id)
        and (
            not endpoint_id
            or not item.get("endpoint_id")
            or str(item.get("endpoint_id") or "") == endpoint_id
        )
    ]
    statuses = [as_int(item.get("status") or item.get("status_code")) for item in scoped]
    statuses = [item for item in statuses if item is not None]
    hashes = [result_hash(item) for item in scoped]
    timings = [
        float(item.get("timing_ms")) for item in scoped if item.get("timing_ms") not in (None, "")
    ]
    status_stable = len(set(statuses)) <= 1 if statuses else False
    body_stable = len(set(hashes)) <= 1 if hashes else False
    timing_median = median(timings) if timings else None
    return {
        "baseline_id": stable_id("baseline", fuzz_id, endpoint_id, hashes, statuses),
        "fuzz_id": fuzz_id,
        "endpoint_id": endpoint_id,
        "sample_count": len(scoped),
        "status_values": sorted(set(statuses)),
        "response_hashes": sorted(set(hashes)),
        "status_stable": status_stable,
        "body_stable": body_stable,
        "stable": status_stable and body_stable and len(scoped) >= 2,
        "timing_median_ms": timing_median,
        "timing_samples_ms": timings,
    }


def baseline_is_stable(baseline: dict[str, Any] | list[dict[str, Any]]) -> bool:
    if isinstance(baseline, list):
        baseline = build_baseline_set(baseline)
    return bool(baseline.get("stable") or baseline.get("baseline_stable"))


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
