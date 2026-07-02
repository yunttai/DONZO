from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scope", type=Path)
    args = parser.parse_args()
    data = yaml.safe_load(args.scope.read_text(encoding="utf-8")) or {}
    print(f"program: {data.get('program_name', 'unknown')}")
    print(f"profile: {data.get('profile', 'unknown')}")
    print(f"mode: {data.get('mode', 'unknown')}")
    print("in_scope.domains:")
    for item in data.get("in_scope", {}).get("domains", []):
        print(f"  - {item}")
    print("out_of_scope.domains:")
    for item in data.get("out_of_scope", {}).get("domains", []):
        print(f"  - {item}")


if __name__ == "__main__":
    main()
