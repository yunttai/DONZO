from __future__ import annotations

from _policy_common import deny, find_secret_patterns, load_payload, payload_text

HIGH_RISK_TERMS = (
    "credential_stuffing",
    "password_spraying",
    "bruteforce",
    "brute force",
    "dos",
    "ddos",
    "destructive",
    "session hijack",
    "takeover claim",
    "automatic submission",
)


def main() -> None:
    text = payload_text(load_payload()).lower()
    if find_secret_patterns(text):
        deny("Permission request contains secret-like material.")
    for term in HIGH_RISK_TERMS:
        if term in text:
            deny(f"Permission request includes forbidden activity: {term}")


if __name__ == "__main__":
    main()
