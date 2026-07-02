from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


def load_data(path: Path, data_format: str) -> Any:
    text = path.read_text(encoding="utf-8")
    if data_format == "auto":
        data_format = "yaml" if path.suffix.lower() in {".yaml", ".yml"} else "json"
    if data_format == "yaml":
        return yaml.safe_load(text)
    return json.loads(text)


def validate_file(schema_path: Path, input_path: Path, data_format: str = "auto") -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    data = load_data(input_path, data_format)
    validator = Draft202012Validator(schema)
    return [error.message for error in sorted(validator.iter_errors(data), key=str)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--format", choices=["auto", "json", "yaml"], default="auto")
    args = parser.parse_args()

    errors = validate_file(args.schema, args.input, args.format)
    if errors:
        print(json.dumps({"valid": False, "errors": errors}, indent=2))
        raise SystemExit(2)
    print(json.dumps({"valid": True, "errors": []}, indent=2))


if __name__ == "__main__":
    main()
