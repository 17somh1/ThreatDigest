"""Deterministic filtering and ranking for threat items."""

from __future__ import annotations

from src.extract import extract_text

KEYWORDS = [
    "cve-",
    "zero-day",
    "0-day",
    "actively exploited",
    "exploited",
    "known exploited",
    "kev",
    "security advisory",
    "patch",
    "ransomware",
    "data leak",
    "supply chain",
    "credential",
    "phishing",
]

AUTHORITATIVE_SOURCES = [
    "cisa",
    "ncsc",
    "msrc",
    "microsoft security response center",
    "google threat intelligence",
]

HIGH_URGENCY_HINTS = [
    "actively exploited",
    "in the wild",
    "known exploited",
    "kev",
    "security advisory",
    "binding operational directive",
]

RETROSPECTIVE_HINTS = [
    "last year",
    "annual report",
    "trend report",
    "survey",
    "outlook",
    "roundup",
    "retrospective",
]


def _matches_keywords(text: str) -> bool:
    lower = text.lower()
    return any(keyword in lower for keyword in KEYWORDS)


def _is_authoritative(source: str) -> bool:
    lower = source.lower()
    return any(name in lower for name in AUTHORITATIVE_SOURCES)


def _contains_any(text: str, values: list[str]) -> bool:
    return any(value in text for value in values)


def filter_items(items: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    for item in items:
        summary_text = extract_text(item.get("summary", ""))
        combined = f"{item.get('title', '')} {summary_text}"
        if (
            _matches_keywords(combined)
            or _contains_any(combined.lower(), HIGH_URGENCY_HINTS)
            or _is_authoritative(item.get("source", ""))
        ):
            item["summary"] = summary_text
            filtered.append(item)
    return filtered


def score_item(item: dict) -> int:
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    score = 0

    if "actively exploited" in text or "in the wild" in text:
        score += 6
    if "known exploited" in text or "kev" in text:
        score += 5
    if "cve-" in text:
        score += 2
    if "zero-day" in text or "0-day" in text:
        score += 3
    if "exploited" in text:
        score += 2
    if "security advisory" in text or "binding operational directive" in text:
        score += 3
    if "patch" in text or "fixed" in text or "update" in text:
        score += 2
    if "ransomware" in text:
        score += 2
    if "data leak" in text:
        score += 2
    if "supply chain" in text:
        score += 2
    if "credential" in text:
        score += 2
    if "phishing" in text:
        score += 2
    if _is_authoritative(item.get("source", "")):
        score += 3

    if _contains_any(text, RETROSPECTIVE_HINTS) and not _contains_any(text, HIGH_URGENCY_HINTS):
        score -= 4

    if len(text) < 140 and score < 6:
        score -= 2

    return score


def rank_items(items: list[dict]) -> list[dict]:
    return sorted(items, key=score_item, reverse=True)
