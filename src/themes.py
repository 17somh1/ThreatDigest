"""Theme extraction for the daily digest."""

from __future__ import annotations

import json
import sys
from typing import Any

from openai import OpenAI

from src.summarise import DEFAULT_MODEL

_REQUIRED_KEYS = {"themes", "today_in_one_sentence"}


class ThemesError(ValueError):
    """Raised when theme output cannot be normalized."""


def _build_prompt(clusters: list[dict]) -> str:
    cluster_notes = "\n".join(
        "\n".join(
            [
                f"- Title: {cluster.get('cluster_title', '').strip()}",
                f"  Risk: {cluster.get('risk', '').strip()}",
                f"  Hook: {cluster.get('hook', '').strip()}",
                f"  Who should care: {cluster.get('who_should_care', '').strip()}",
                f"  Why now: {cluster.get('why_this_is_here', '').strip()}",
                f"  Labels: {', '.join(cluster.get('labels', []))}",
            ]
        )
        for cluster in clusters
    )
    return (
        "You are summarizing today's threat digest patterns for readers who want clear, operator-minded analysis. "
        "Return STRICT JSON with the required keys only.\n\n"
        "Schema:\n"
        "{\n"
        "  \"today_in_one_sentence\": \"1 sentence explaining the day's main operational takeaway in plain English\",\n"
        "  \"themes\": [\"pattern-level theme with plain-English implication\", \"...\", \"...\"]\n"
        "}\n\n"
        "Rules:\n"
        "- Output valid JSON only. No markdown.\n"
        "- Themes must be pattern-level, not headline-level.\n"
        "- Prefer pressure points, attacker behavior, and defender workload over generic observations.\n"
        "- The sentence must be sharp and human, no corporate filler.\n"
        "- Avoid jargon unless you explain it in plain English.\n"
        "- One sentence only for today_in_one_sentence.\n\n"
        f"Digest notes:\n{cluster_notes}\n"
    )


def _normalize_output(data: dict[str, Any]) -> dict[str, Any]:
    if not _REQUIRED_KEYS.issubset(data.keys()):
        missing = ", ".join(sorted(_REQUIRED_KEYS - set(data.keys())))
        raise ThemesError(f"Missing keys: {missing}")

    themes = [str(item).strip() for item in data.get("themes", []) if str(item).strip()]
    if len(themes) < 3:
        raise ThemesError("themes must have 3 entries")

    return {
        "themes": themes[:3],
        "today_in_one_sentence": str(data.get("today_in_one_sentence", "")).strip(),
    }


def generate_themes(
    clusters: list[dict],
    api_key: str,
    model: str | None = None,
) -> dict[str, Any] | None:
    if not clusters:
        return None

    client = OpenAI(api_key=api_key)
    prompt = _build_prompt(clusters)

    try:
        response = client.chat.completions.create(
            model=model or DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "Return only strict JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=200,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or ""
        data = json.loads(content)
        return _normalize_output(data)
    except (json.JSONDecodeError, ThemesError) as exc:
        print(f"Skipping themes due to invalid JSON: {exc}", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"Theme request failed: {exc}", file=sys.stderr)
        return None
