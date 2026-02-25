"""Topic clustering and scoring for the editor layer."""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from src.extract import extract_text

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_VENDOR_HINTS = {
    "cisco",
    "microsoft",
    "google",
    "apple",
    "ivanti",
    "fortinet",
    "palo alto",
    "crowdstrike",
    "okta",
    "citrix",
    "vmware",
    "linux",
    "windows",
    "amazon",
    "aws",
    "azure",
    "gcp",
    "oracle",
    "sap",
    "atlassian",
    "mongodb",
    "postgres",
    "nginx",
    "apache",
}

_STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "to",
    "in",
    "for",
    "on",
    "with",
    "at",
    "by",
    "from",
    "over",
    "about",
    "after",
    "before",
    "as",
    "is",
    "are",
    "be",
    "this",
    "that",
    "new",
    "report",
    "reports",
    "update",
}

_LABEL_KEYWORDS = {
    "ACTIVE_EXPLOITATION": ["actively exploited", "in the wild", "active exploitation"],
    "KEV_ADDED": ["kev", "known exploited", "emergency directive"],
    "GUIDANCE": ["guidance", "advisory", "best practice", "recommendations"],
    "PATCH_RELEASE": ["patch", "update", "fixed", "release", "hotfix"],
    "INDUSTRY_SIGNAL": ["report", "trend", "survey", "outlook"],
    "LEGAL_POLICY": ["law", "regulation", "policy", "compliance", "sanction"],
    "RESEARCH": ["research", "analysis", "disclosure", "paper"],
}


def _tokenize(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [token for token in tokens if token not in _STOPWORDS and len(token) > 2]


def _title_tokens(title: str) -> set[str]:
    return set(_tokenize(title))


def extract_topic_key(item: dict) -> str:
    title = item.get("title", "") or ""
    summary = item.get("summary", "") or ""
    combined = f"{title} {summary}"

    cve_match = _CVE_RE.search(combined)
    if cve_match:
        return cve_match.group(0).upper()

    lower = combined.lower()
    vendor_hits = [vendor for vendor in _VENDOR_HINTS if vendor in lower]
    if vendor_hits:
        vendor = sorted(vendor_hits, key=len, reverse=True)[0]
        tokens = _tokenize(title)
        if tokens:
            return f"{vendor} {tokens[0]}"
        return vendor

    tokens = _tokenize(title)
    if not tokens:
        return "misc"

    counts = Counter(tokens)
    top = [word for word, _ in counts.most_common(3)]
    return " ".join(top)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _item_text(item: dict) -> str:
    summary = extract_text(item.get("summary", ""))
    return f"{item.get('title', '')} {summary}"


def cluster_items(items: Iterable[dict]) -> list[dict]:
    clusters: list[dict] = []

    for item in items:
        topic_key = extract_topic_key(item)
        tokens = _title_tokens(item.get("title", ""))

        assigned = False
        for cluster in clusters:
            if cluster["topic_key"] == topic_key:
                cluster["items"].append(item)
                cluster["tokens"].update(tokens)
                assigned = True
                break

            overlap = _jaccard(cluster["tokens"], tokens)
            if overlap >= 0.5:
                cluster["items"].append(item)
                cluster["tokens"].update(tokens)
                assigned = True
                break

        if not assigned:
            clusters.append(
                {
                    "topic_key": topic_key,
                    "items": [item],
                    "tokens": set(tokens),
                }
            )

    return clusters


def score_item(item: dict) -> int:
    text = _item_text(item).lower()
    score = 0

    if "actively exploited" in text or "in the wild" in text:
        score += 5
    if "kev" in text or "known exploited" in text or "emergency directive" in text:
        score += 4
    if "zero-day" in text or "0-day" in text or "rce" in text or "auth bypass" in text:
        score += 3
    if _CVE_RE.search(text):
        score += 2
    if item.get("source", "").lower().startswith("cisa"):
        score += 2

    if "policy" in text or "regulation" in text or "law" in text:
        score -= 2

    return score


def score_cluster(cluster: dict) -> int:
    item_scores = [score_item(item) for item in cluster["items"]]
    base = max(item_scores) if item_scores else 0
    if len(cluster["items"]) > 1:
        base += 1
    return base


def label_cluster(cluster: dict) -> list[str]:
    text = " ".join(_item_text(item) for item in cluster["items"]).lower()
    labels: list[str] = []
    for label, keywords in _LABEL_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            labels.append(label)

    if not labels:
        labels.append("INDUSTRY_SIGNAL")

    return labels
