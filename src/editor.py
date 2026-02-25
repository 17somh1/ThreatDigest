"""Editorial layer to cluster, prioritize, and format stories."""

from __future__ import annotations

from dataclasses import dataclass
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
            cleaned = str(entry).strip()
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
                "title": item.get("title", ""),
                "url": url,
                "source": item.get("source", ""),
                "published": item.get("published", ""),
            }
        )
        if len(sources) >= 3:
            break
    return sources


def _risk_from_items(items: list[dict]) -> str:
    best = "LOW"
    for item in items:
        risk = str(item.get("risk", "LOW")).upper()
        if _RISK_ORDER.get(risk, 1) > _RISK_ORDER.get(best, 1):
            best = risk
    return best


def _confidence_from_items(items: list[dict]) -> str:
    if len(items) > 1:
        return "HIGH"
    confidence = str(items[0].get("confidence", "LOW")).upper() if items else "LOW"
    return confidence


def _story_lines(primary: dict, sources: list[dict]) -> list[str]:
    lines = []
    for line in (primary.get("what_happened", "") or "").split("."):
        cleaned = line.strip()
        if cleaned:
            lines.append(f"- {cleaned}.")
    for line in (primary.get("why_it_matters", "") or "").split("."):
        cleaned = line.strip()
        if cleaned:
            lines.append(f"- {cleaned}.")

    if len(sources) > 1:
        also = ", ".join(source.get("source", "") for source in sources[1:])
        lines.append(f"- Also reported by {also}.")

    return lines[:8]


def _why_this_is_here(cluster_score: int, source_count: int) -> str:
    if cluster_score >= 6:
        reason = "High-severity signals and credible reporting."
    elif cluster_score >= 4:
        reason = "Meaningful risk with actionable signals."
    else:
        reason = "Relevant context worth tracking."
    if source_count > 1:
        reason = f"{reason} Multiple sources confirm the story."
    return reason


def _build_cluster(cluster_payload: dict) -> dict:
    items = cluster_payload["items"]
    primary = _choose_primary_item(items)
    sources = _merge_sources(items)

    return {
        "cluster_id": cluster_payload["topic_key"],
        "cluster_title": primary.get("title", "Untitled"),
        "labels": cluster.label_cluster(cluster_payload),
        "risk": _risk_from_items(items),
        "confidence": _confidence_from_items(items),
        "attack_stage": primary.get("attack_stage", "Unknown"),
        "why_this_is_here": _why_this_is_here(cluster.score_cluster(cluster_payload), len(items)),
        "spicy_take": primary.get("spicy_take", ""),
        "tl_dr": primary.get("tl_dr", ""),
        "the_story": "\n".join(_story_lines(primary, sources)),
        "beginner_breakdown": _merge_beginner_breakdown(items),
        "soc_focus": primary.get("soc_focus", []) or [],
        "recommended_actions": primary.get("recommended_actions", []) or [],
        "sources": sources,
        "_score": cluster.score_cluster(cluster_payload),
    }


def build_editorial(items: list[dict], max_clusters: int = 8) -> EditorialSelection:
    raw_clusters = cluster.cluster_items(items)
    clusters = [_build_cluster(payload) for payload in raw_clusters]
    clusters.sort(key=lambda item: item.get("_score", 0), reverse=True)

    clusters = clusters[:max_clusters]

    top_story = clusters[0] if clusters else None
    top_three = clusters[1:3] if len(clusters) > 1 else []
    context = clusters[3:] if len(clusters) > 3 else []

    return EditorialSelection(
        top_story=top_story,
        top_three=top_three,
        context=context,
        all_clusters=clusters,
    )
