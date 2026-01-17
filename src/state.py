"""State management for deduping processed URLs."""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Deque

STATE_PATH = Path("state.json")
MAX_URLS = 2000


def _default_state() -> dict:
    return {
        "last_run_utc": "",
        "processed_urls": [],
    }


def load_state() -> dict:
    if not STATE_PATH.exists():
        return _default_state()

    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return _default_state()

    if "processed_urls" not in data or not isinstance(data["processed_urls"], list):
        data["processed_urls"] = []
    if "last_run_utc" not in data:
        data["last_run_utc"] = ""
    return data


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def should_process(state: dict, url: str | None) -> bool:
    if not url:
        return False
    processed = set(state.get("processed_urls", []))
    return url not in processed


def mark_processed(state: dict, url: str | None) -> None:
    if not url:
        return
    existing = deque(state.get("processed_urls", []), maxlen=MAX_URLS)
    if url in existing:
        return
    existing.append(url)
    state["processed_urls"] = list(existing)
