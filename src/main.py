"""Entry point for the ThreatDigest pipeline."""

from __future__ import annotations

import os
import sys

REQUIRED_ENV_VARS = [
    "FEEDLY_TOKEN",
    "OPENAI_API_KEY",
    "EMAIL_API_KEY",
    "TO_EMAIL",
    "FROM_EMAIL",
]


def find_missing_env_vars() -> list[str]:
    missing = []
    for name in REQUIRED_ENV_VARS:
        if not os.getenv(name):
            missing.append(name)
    return missing


def main() -> int:
    if os.getenv("SKIP_ENV_CHECK") != "1":
        missing = find_missing_env_vars()
        if missing:
            for name in missing:
                print(f"Missing {name}", file=sys.stderr)
            return 1

    print("hello digest pipeline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
