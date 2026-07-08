from __future__ import annotations

from statistics import median
from typing import Any

from donzo.fuzzing.baseline import build_baseline_set
from donzo.fuzzing.response_normalizer import response_similarity, result_body, result_hash
from donzo.oracles.verdict import coerce_bool, oracle_verdict

DB_ERROR_MARKERS = {
    "sql",
    "syntax",
    "database",
    "mysql",
    "postgres",
    "sqlite",
    "odbc",
    "jdbc",
    "orm",
}


def evaluate_sqli_boolean_differential(
    baseline: list[dict[str, Any]] | dict[str, Any],
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline_set = baseline if isinstance(baseline, dict) else build_baseline_set(baseline)
    if not baseline_set.get("stable"):
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "baseline responses are not stable enough for SQLi differential confirmation",
            needs_more_evidence=["stable repeated baseline responses"],
        )
    true_probes = role_records(probes, "true")
    false_probes = role_records(probes, "false")
    if not true_probes or not false_probes:
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "SQLi boolean differential requires true-like and false-like probe observations",
            needs_more_evidence=["true_condition_probe", "false_condition_probe"],
        )
    baseline_hash = first_hash(baseline_set, baseline if isinstance(baseline, list) else [])
    true_like = all(record_matches_hash(item, baseline_hash) for item in true_probes)
    false_different = all(not record_matches_hash(item, baseline_hash) for item in false_probes)
    control_different = any(not record_matches_hash(item, baseline_hash) for item in controls)
    if true_like and false_different and not control_different:
        return oracle_verdict(
            "confirmed",
            0.94,
            (
                "true-like SQLi mutation stayed baseline-like while false-like "
                "mutation differed and controls did not"
            ),
            "high",
            evidence=[
                "baseline stable",
                "true mutation baseline-like",
                "false mutation consistently different",
                "control mutation did not reproduce difference",
            ],
        )
    if false_different and control_different:
        return oracle_verdict(
            "false_positive",
            0.72,
            (
                "control mutation also changed the response, so the "
                "SQLi-specific differential is not isolated"
            ),
            false_positive_reasons=["generic input validation or instability"],
        )
    return oracle_verdict(
        "probable",
        0.62,
        "SQLi differential signal exists but does not satisfy all confirmation controls",
        "medium",
        needs_more_evidence=["repeat probes", "independent oracle such as error or timing"],
    )


def evaluate_sqli_time_differential(
    baseline: list[dict[str, Any]] | dict[str, Any],
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline_set = baseline if isinstance(baseline, dict) else build_baseline_set(baseline)
    base_median = baseline_set.get("timing_median_ms")
    if base_median is None:
        return oracle_verdict(
            "needs_more_evidence",
            0.3,
            "timing oracle requires baseline timing samples",
            needs_more_evidence=["baseline timing samples"],
        )
    control_times = timing_values(controls)
    probe_times = timing_values(probes)
    if len(probe_times) < 2:
        return oracle_verdict(
            "needs_more_evidence",
            0.35,
            "timing oracle requires repeated timing probes",
            needs_more_evidence=["repeated timing probe samples"],
        )
    threshold = float((context or {}).get("minimum_delay_ms") or 750)
    control_median = median(control_times) if control_times else float(base_median)
    probe_median = median(probe_times)
    if probe_median - max(float(base_median), control_median) >= threshold:
        return oracle_verdict(
            "confirmed",
            0.9,
            "time mutation repeatedly exceeded baseline/control timing by the configured threshold",
            "high",
            evidence=["stable timing baseline", "control timing normal", "time mutation delayed"],
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.45,
        "timing difference is below confirmation threshold",
        needs_more_evidence=["larger repeated timing differential or another oracle"],
    )


def evaluate_sqli_error(
    baseline: list[dict[str, Any]] | dict[str, Any],
    controls: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    probe_errors = [item for item in probes if has_db_error(item)]
    control_errors = [item for item in controls if has_db_error(item)]
    if probe_errors and not control_errors:
        return oracle_verdict(
            "confirmed",
            0.86,
            "database or ORM error signature appeared only for the targeted mutation",
            "high",
            evidence=["targeted mutation produced DB/ORM error", "controls did not"],
        )
    if probe_errors and control_errors:
        return oracle_verdict(
            "false_positive",
            0.7,
            "control inputs produced the same database-like error signal",
            false_positive_reasons=["generic malformed-input error"],
        )
    return oracle_verdict(
        "needs_more_evidence",
        0.35,
        "no SQL-specific error signature was observed",
        needs_more_evidence=["SQL-specific error signature or differential oracle"],
    )


def role_records(records: list[dict[str, Any]], marker: str) -> list[dict[str, Any]]:
    marker = marker.lower()
    return [
        item
        for item in records
        if marker
        in " ".join(
            str(item.get(key) or "") for key in ("probe_role", "role", "mutation_kind")
        ).lower()
    ]


def first_hash(baseline_set: dict[str, Any], baseline_records: list[dict[str, Any]]) -> str:
    hashes = baseline_set.get("response_hashes") or []
    if hashes:
        return str(hashes[0])
    if baseline_records:
        return result_hash(baseline_records[0])
    return ""


def record_matches_hash(record: dict[str, Any], expected_hash: str) -> bool:
    if expected_hash and result_hash(record) == expected_hash:
        return True
    similarity = record.get("response_similarity_to_baseline")
    if similarity is not None:
        try:
            return float(similarity) >= 0.95
        except (TypeError, ValueError):
            return False
    return response_similarity(result_body(record), record.get("baseline_body") or "") >= 0.95


def timing_values(records: list[dict[str, Any]]) -> list[float]:
    return [
        float(item.get("timing_ms")) for item in records if item.get("timing_ms") not in (None, "")
    ]


def has_db_error(record: dict[str, Any]) -> bool:
    if coerce_bool(record.get("db_error") or record.get("sql_error")):
        return True
    text = " ".join(
        str(record.get(key) or "") for key in ("error_signature", "error", "body", "response_body")
    ).lower()
    return any(marker in text for marker in DB_ERROR_MARKERS)
