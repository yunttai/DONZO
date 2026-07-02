from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    from harness.scripts.normalize_findings import normalize_record

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="JSON object file. Reads stdin if omitted.")
    args = parser.parse_args()
    raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    record = json.loads(raw)
    print(json.dumps(normalize_record(record), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
