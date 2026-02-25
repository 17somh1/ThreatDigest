"""Editorial layer to cluster, prioritize, and format stories."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from src import cluster


_RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class EditorialSelection:
    top_story: dict | None
    top_three: list[dict]
    context: list[dict]
    all_clusters: list[dict]


def _choose_primary_item(items: list[dict]) -> dict:
    return max(items, key=cluster.score_item)


def _merge_beginner_breakdown(items: Iterable[dict]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for item in items:
        for entry in item.get("beginner_breakdown", []) or []:
            cleaned = _clean_text(entry)
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                merged.append(cleaned)
    return merged[:6]


def _merge_sources(items: Iterable[dict]) -> list[dict]:
    sources = []
    seen_urls = set()
    for item in items:
        url = item.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        sources.append(
            {
                "title": _clean_text(item.get("title", "")),
                "url": url,
                "source": _clean_text(item.get("source", "")),
                "published": _clean_text(item.get("published", "")),
            }
        )
        if len(sources) >= 3:
            break
    return sources


def _clean_text(text: str) -> str:
    cleaned = " ".join(str(text).split())
    cleaned = cleaned.replace("U. S.", "U.S.")
    cleaned = re.sub(r"(\\d)\\s+\\.\\s+(\\d)", r"\\1.\\2", cleaned)
    cleaned = cleaned.replace("U. K.", "U.K.")
    return cleaned.strip()


def _risk_from_items(items: list[dict]) -> str:
    best = "LOW"
    for item in items:
        risk = str(item.get("risk", "LOW")).upper()
        if _RISK_ORDER.get(risk, 1) > _RISK_ORDER.get(best, 1):
            best = risk
    return best


def _confidence_from_signals(signals: dict, sources: set[str]) -> str:
    has_authority = any(source.startswith("cisa") for source in sources)
    if signals.get("kev") and signals.get("multi_source"):
        return "HIGH"
    if signals.get("active_exploit") and (signals.get("multi_source") or has_authority):
        return "HIGH"
    if signals.get("multi_source") or has_authority:
        return "MEDIUM"
    return "LOW"


def _split_sentences(text: str) -> list[str]:
    cleaned = _clean_text(text)
    if not cleaned:
        return []
    parts = re.split(r"(?<=[.!?])\\s+(?=[A-Z0-9])", cleaned)
    return [part.strip() for part in parts if part.strip()]


def _story_lines(primary: dict, sources: list[dict]) -> list[str]:
    lines = []
    lines.extend(_split_sentences(primary.get("tl_dr", "")))
    lines.extend(_split_sentences(primary.get("what_happened", "")))
    lines.extend(_split_sentences(primary.get("why_it_matters", "")))

    if len(sources) > 1:
        also = ", ".join(source.get("source", "") for source in sources[1:])
        lines.append(f"Also reported by {also}.")

    lines = [f"- {_clean_text(line)}" for line in lines if line]
    if len(lines) < 4:
        lines.append("- Expect follow-on reporting as more details surface.")
    return lines[:8]


def _why_this_is_here(signals: dict) -> str:
    reasons = []
    if signals.get("active_exploit"):
        reasons.append("Active exploitation signals mean this needs attention now.")
    if signals.get("kev"):
        reasons.append("KEV listing shrinks the patch window.")
    if signals.get("patch"):
        reasons.append("Patch release for widely deployed software.")
    if signals.get("multi_source"):
        reasons.append("Multiple sources confirm the same issue.")
    if signals.get("sector"):
        reasons.append("Sector impact makes this more than a one-off.")

    if not reasons:
        reasons.append("Context worth tracking while details firm up.")

    return " ".join(reasons[:2])


def _signals_from_items(items: list[dict]) -> dict:
    text = " ".join(cluster._item_text(item) for item in items).lower()
    sources = {str(item.get("source", "")).lower() for item in items}
    return {
        "active_exploit": "actively exploited" in text or "in the wild" in text,
        "kev": "kev" in text or "known exploited" in text,
        "patch": "patch" in text or "fixed" in text or "update" in text,
        "sector": any(keyword in text for keyword in ("healthcare", "finance", "government", "critical infrastructure")),
        "multi_source": len(sources) > 1,
        "sources": sources,
    }


def _build_cluster(cluster_payload: dict) -> dict:
    items = cluster_payload["items"]
    primary = _choose_primary_item(items)
    sources = _merge_sources(items)
    signals = _signals_from_items(items)
    spicy_take = _clean_text(primary.get("spicy_take", ""))
    if spicy_take.lower().startswith("because who"):
        spicy_take = "If this is exposed, assume scanning already started."

    return {
        "cluster_id": cluster_payload["topic_key"],
        "cluster_title": _clean_text(primary.get("title", "Untitled")),
        "labels": cluster.label_cluster(cluster_payload),
        "risk": _risk_from_items(items),
        "confidence": _confidence_from_signals(signals, signals.get("sources", set())),
        "attack_stage": primary.get("attack_stage", "Unknown"),
        "why_this_is_here": _why_this_is_here(signals),
        "spicy_take": spicy_take,
        "tl_dr": _clean_text(primary.get("tl_dr", "")),
        "the_story": "\n".join(_story_lines(primary, sources)),
        "beginner_breakdown": _merge_beginner_breakdown(items),
        "soc_focus": [_clean_text(entry) for entry in (primary.get("soc_focus", []) or [])],
        "recommended_actions": [_clean_text(entry) for entry in (primary.get("recommended_actions", []) or [])],
        "sources": sources,
        "_score": cluster.score_cluster(cluster_payload),
        "_vendor_key": cluster_payload.get("vendor_key", ""),
    }


def build_editorial(items: list[dict], max_clusters: int = 6) -> EditorialSelection:
    raw_clusters = cluster.cluster_items(items)
    clusters = [_build_cluster(payload) for payload in raw_clusters]
    clusters.sort(key=lambda item: item.get("_score", 0), reverse=True)

    clusters = clusters[:max_clusters]

    top_story = clusters[0] if clusters else None
    top_vendor = top_story.get("_vendor_key") if top_story else ""

    top_three: list[dict] = []
    for candidate in clusters[1:]:
        if len(top_three) >= 2:
            break
        if top_vendor and candidate.get("_vendor_key") == top_vendor:
            continue
        top_three.append(candidate)

    used_ids = {item.get("cluster_id") for item in top_three}
    context = [
        item for item in clusters[1:]
        if item.get("cluster_id") not in used_ids and item is not top_story
    ]

    return EditorialSelection(
        top_story=top_story,
        top_three=top_three,
        context=context,
        all_clusters=clusters,
    )
