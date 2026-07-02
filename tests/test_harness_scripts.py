from __future__ import annotations

from pathlib import Path

from harness.scripts.dedupe_findings import dedupe_records
from harness.scripts.normalize_findings import normalize_record
from harness.scripts.redact_secrets import redact_text
from harness.scripts.validate_scope import validate_scope_file


def test_scope_example_is_valid() -> None:
    result = validate_scope_file(Path("scope.example.yaml"))
    assert result["valid"] is True
    assert result["mode"] == "authorized-only"


def test_redact_secret_like_values() -> None:
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    redacted = redact_text(text)
    assert "ghp_" not in redacted
    assert "[REDACTED]" in redacted


def test_normalize_finding_defaults_to_manual_review() -> None:
    finding = normalize_record(
        {
            "title": "Public Swagger UI",
            "severity": "moderate",
            "url": "https://api.example.com/swagger-ui/",
            "tool": "fixture",
        }
    )
    assert finding["severity"] == "medium"
    assert finding["auto_exploit"] is False
    assert finding["verification_status"] == "needs_manual_review"


def test_dedupe_findings_by_normalized_key() -> None:
    finding = normalize_record(
        {
            "title": "Public Swagger UI",
            "severity": "medium",
            "url": "https://api.example.com/swagger-ui/",
            "tool": "fixture",
        }
    )
    assert len(dedupe_records([finding, dict(finding)])) == 1
