"""Entry point for the ThreatDigest pipeline."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ is None or __package__ == "":
    # Allow running via `python src/main.py` without module resolution errors.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import dedupe
from src import feeds
from src import rank
from src import render
from src import state
from src import summarise
from src import themes

CONFIG_PATH = Path("config/settings.yaml")
ENV_PATH = Path(".env")
TEMPLATE_PATH = Path("templates/index.html.j2")
DOCS_DIR = Path("docs")
ARCHIVE_DIR = DOCS_DIR / "archive"

DEFAULT_MAX_ITEMS = 15
DEFAULT_RECENT_HOURS = 48


def load_dotenv() -> None:
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def _read_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _is_recent(item: dict, cutoff: datetime) -> bool:
    published_dt = item.get("published_dt")
    if not published_dt:
        return False
    return published_dt >= cutoff


def _ensure_dirs() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def _sync_archives(digest_date: str, keep_days: int = 14) -> list[str]:
    archives = [path.stem for path in ARCHIVE_DIR.glob("*.html")]
    if digest_date not in archives:
        archives.append(digest_date)
    archives = sorted(set(archives), reverse=True)
    keep_set = set(archives[:keep_days])

    for path in ARCHIVE_DIR.glob("*.html"):
        if path.stem not in keep_set:
            path.unlink()

    return sorted(keep_set, reverse=True)


def main() -> int:
    load_dotenv()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Missing OPENAI_API_KEY", file=sys.stderr)
        return 1

    max_items = _read_int_env("MAX_ITEMS", DEFAULT_MAX_ITEMS)
    recent_hours = _read_int_env("RECENT_HOURS", DEFAULT_RECENT_HOURS)
    model = os.getenv("OPENAI_MODEL") or None
    tone_mode = os.getenv("TONE_MODE", "spicy").strip().lower()
    if tone_mode not in {"spicy", "clean"}:
        tone_mode = "spicy"

    feed_urls = feeds.load_feed_urls(CONFIG_PATH)
    entries = feeds.fetch_entries(feed_urls)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=recent_hours)
    recent_entries = [entry for entry in entries if _is_recent(entry, cutoff)]

    deduped_entries = dedupe.dedupe_items(recent_entries)
    filtered_entries = rank.filter_items(deduped_entries)
    if not filtered_entries:
        filtered_entries = deduped_entries
    ranked_entries = rank.rank_items(filtered_entries)

    digest_state = state.load_state()
    new_entries = [
        entry for entry in ranked_entries if state.should_process(digest_state, entry.get("url"))
    ]
    selected_entries = new_entries[:max_items]

    print(f"Fetched {len(entries)} entries from RSS feeds")
    print(f"Recent entries (last {recent_hours}h): {len(recent_entries)}")
    print(f"After dedupe: {len(deduped_entries)}")
    print(f"After keyword filtering: {len(filtered_entries)}")
    print(f"Selected for summarization: {len(selected_entries)}")

    summarized_items: list[dict] = []
    for entry in selected_entries:
        summary = summarise.summarize_item(
            entry,
            api_key=api_key,
            tone_mode=tone_mode,
            model=model,
        )
        if not summary:
            continue
        entry.update(summary)
        summarized_items.append(entry)
        state.mark_processed(digest_state, entry.get("url"))

    now = datetime.now(timezone.utc)
    digest_state["last_run_utc"] = now.isoformat()
    state.save_state(digest_state)

    digest_date = now.strftime("%Y-%m-%d")
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")

    _ensure_dirs()
    archive_links = _sync_archives(digest_date, keep_days=14)

    themes_data = themes.generate_themes(summarized_items, api_key=api_key, model=model)

    html = render.render_digest(
        summarized_items,
        digest_date=digest_date,
        generated_at=generated_at,
        archive_links=archive_links,
        template_path=TEMPLATE_PATH,
        themes_data=themes_data,
        tone_mode=tone_mode,
    )

    index_path = DOCS_DIR / "index.html"
    archive_path = ARCHIVE_DIR / f"{digest_date}.html"
    index_path.write_text(html, encoding="utf-8")
    archive_path.write_text(html, encoding="utf-8")

    print(f"Wrote {index_path}")
    print(f"Wrote {archive_path}")
    print(f"Summarized items: {len(summarized_items)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
