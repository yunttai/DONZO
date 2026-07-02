from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from _policy_common import load_payload, payload_text


def main() -> None:
    out_dir = Path("artifacts/codex")
    out_dir.mkdir(parents=True, exist_ok=True)
    text = payload_text(load_payload()).strip()
    summary = [
        "# Codex Stop Summary",
        "",
        f"- timestamp: {datetime.now(UTC).isoformat()}",
        "- safety: scope and redaction rules remain authoritative",
    ]
    if text:
        summary.extend(["", "## Payload", "", text[:4000]])
    (out_dir / "last-summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
