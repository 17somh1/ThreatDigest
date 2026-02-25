"""RSS/Atom feed ingestion."""

from __future__ import annotations

import sys

import feedparser

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


def fetch_entries(feed_urls: list[str] | None = None) -> list[dict]:
    feeds = feed_urls or DEFAULT_FEEDS
    items: list[dict] = []
    for feed_url in feeds:
        try:
            raw = fetch_url(feed_url)
        except Exception as exc:
            print(f"Failed to fetch feed {feed_url}: {exc}", file=sys.stderr)
            continue

        parsed = feedparser.parse(raw)
        feed_title = parsed.feed.get("title", feed_url)
        for entry in parsed.entries:
            items.append(
                {
                    "title": (entry.get("title") or "").strip(),
                    "url": entry.get("link"),
                    "published": entry.get("published") or entry.get("updated") or "",
                    "source": feed_title,
                    "summary": entry.get("summary") or entry.get("description") or "",
                }
            )
    return items
