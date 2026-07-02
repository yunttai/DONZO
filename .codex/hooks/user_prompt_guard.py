from __future__ import annotations

from _policy_common import deny, find_secret_patterns, load_payload, payload_text


def main() -> None:
    payload = load_payload()
    text = payload_text(payload)
    matches = find_secret_patterns(text)
    if matches:
        deny("Prompt appears to contain secret-like material. Redact it before continuing.")


if __name__ == "__main__":
    main()
