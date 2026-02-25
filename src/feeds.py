"""Feed ingestion and normalization."""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable

import feedparser
import yaml

from src.fetch import fetch_url

DEFAULT_FEEDS = [
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "https://www.cisa.gov/uscert/ncas/current-activity.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://thehackernews.com/feeds/posts/default",
    "https://krebsonsecurity.com/feed/",
    "https://msrc.microsoft.com/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
]


def load_feed_urls(config_path: Path) -> list[str]:
    if not config_path.exists():
        return DEFAULT_FEEDS

    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    feeds = data.get("feeds") or []
    if not feeds:
        return DEFAULT_FEEDS
    return feeds


def _parse_datetime(value: str | None, fallback: time.struct_time | None) -> datetime | None:
    if value:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            pass
    if fallback:
        return datetime.fromtimestamp(time.mktime(fallback), tz=timezone.utc)
    return None


def fetch_entries(feed_urls: Iterable[str]) -> list[dict]:
    items: list[dict] = []
    for feed_url in feed_urls:
        try:
            raw = fetch_url(feed_url)
        except Exception as exc:
            print(f"Failed to fetch feed {feed_url}: {exc}", file=sys.stderr)
            continue

        parsed = feedparser.parse(raw)
        feed_title = parsed.feed.get("title", feed_url)
        for entry in parsed.entries:
            published = entry.get("published") or entry.get("updated") or ""
            published_dt = _parse_datetime(published, entry.get("published_parsed"))
            items.append(
                {
                    "title": (entry.get("title") or "").strip(),
                    "url": entry.get("link") or entry.get("id"),
                    "published": published,
                    "published_dt": published_dt,
                    "source": feed_title,
                    "summary": entry.get("summary") or entry.get("description") or "",
                }
            )
    return items
