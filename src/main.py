"""Entry point for the ThreatDigest pipeline."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

if __package__ is None or __package__ == "":
    # Allow running via `python src/main.py` without module resolution errors.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import rss
from src import state

REQUIRED_ENV_VARS = [
    "OPENAI_API_KEY",
    "EMAIL_API_KEY",
    "TO_EMAIL",
    "FROM_EMAIL",
]
CONFIG_PATH = Path("config/settings.yaml")


def find_missing_env_vars() -> list[str]:
    missing = []
    for name in REQUIRED_ENV_VARS:
        if not os.getenv(name):
            missing.append(name)
    return missing


def load_feed_urls() -> list[str]:
    if not CONFIG_PATH.exists():
        return rss.DEFAULT_FEEDS

    data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    feeds = data.get("feeds") or []
    if not feeds:
        return rss.DEFAULT_FEEDS
    return feeds


def main() -> int:
    if os.getenv("SKIP_ENV_CHECK") != "1":
        missing = find_missing_env_vars()
        if missing:
            for name in missing:
                print(f"Missing {name}", file=sys.stderr)
            return 1

    feed_urls = load_feed_urls()
    entries = rss.fetch_entries(feed_urls)
    digest_state = state.load_state()
    new_entries = [entry for entry in entries if state.should_process(digest_state, entry.get("url"))]
    for entry in new_entries:
        state.mark_processed(digest_state, entry.get("url"))
    state.save_state(digest_state)

    print("hello digest pipeline")
    print(f"Fetched {len(entries)} entries from RSS feeds")
    print(f"New entries after dedupe: {len(new_entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
