"""OpenAI summarization with strict JSON output."""

from __future__ import annotations

import json
import sys
from typing import Any

from openai import OpenAI

from src.extract import extract_text

DEFAULT_MODEL = "gpt-4o-mini"

_REQUIRED_KEYS = {
    "risk",
    "confidence",
    "summary_bullets",
    "impact",
    "who_affected",
    "actions",
    "tags",
}


class SummarizationError(ValueError):
    """Raised when model output cannot be normalized."""


def _build_prompt(item: dict) -> str:
    summary_text = extract_text(item.get("summary", ""))
    return (
        "You are a cybersecurity analyst producing a daily threat digest. "
        "Summarize the item strictly as JSON with the required keys only. "
        "Keep it concise and factual.\n\n"
        "Required JSON schema:\n"
        "{\n"
        "  \"risk\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"confidence\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"summary_bullets\": [\"...\", \"...\", \"...\"],\n"
        "  \"impact\": \"...\",\n"
        "  \"who_affected\": \"...\",\n"
        "  \"actions\": [\"...\", \"...\", \"...\"],\n"
        "  \"tags\": [\"...\", \"...\"]\n"
        "}\n\n"
        "Constraints:\n"
        "- Output valid JSON only, no extra text.\n"
        "- summary_bullets: exactly 3 short bullets.\n"
        "- actions: up to 3 items.\n"
        "- tags: 2-6 short tags.\n\n"
        "Item:\n"
        f"Title: {item.get('title', '').strip()}\n"
        f"Source: {item.get('source', '').strip()}\n"
        f"Published: {item.get('published', '').strip()}\n"
        f"URL: {item.get('url', '').strip()}\n"
        f"Summary: {summary_text}\n"
    )


def _normalize_output(data: dict[str, Any]) -> dict[str, Any]:
    if not _REQUIRED_KEYS.issubset(data.keys()):
        missing = ", ".join(sorted(_REQUIRED_KEYS - set(data.keys())))
        raise SummarizationError(f"Missing keys: {missing}")

    risk = str(data.get("risk", "")).upper()
    confidence = str(data.get("confidence", "")).upper()
    if risk not in {"LOW", "MEDIUM", "HIGH"}:
        raise SummarizationError("Invalid risk value")
    if confidence not in {"LOW", "MEDIUM", "HIGH"}:
        raise SummarizationError("Invalid confidence value")

    summary_bullets = [str(item).strip() for item in data.get("summary_bullets", []) if str(item).strip()]
    actions = [str(item).strip() for item in data.get("actions", []) if str(item).strip()]
    tags = [str(item).strip() for item in data.get("tags", []) if str(item).strip()]

    if len(summary_bullets) < 3:
        raise SummarizationError("summary_bullets must have 3 entries")

    return {
        "risk": risk,
        "confidence": confidence,
        "summary_bullets": summary_bullets[:3],
        "impact": str(data.get("impact", "")).strip(),
        "who_affected": str(data.get("who_affected", "")).strip(),
        "actions": actions[:3],
        "tags": tags[:6],
    }


def summarize_item(
    item: dict,
    api_key: str,
    model: str | None = None,
    max_retries: int = 1,
) -> dict[str, Any] | None:
    client = OpenAI(api_key=api_key)
    prompt = _build_prompt(item)
    attempts = max_retries + 1

    for attempt in range(attempts):
        try:
            response = client.chat.completions.create(
                model=model or DEFAULT_MODEL,
                messages=[
                    {"role": "system", "content": "Return only strict JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=350,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content or ""
            data = json.loads(content)
            return _normalize_output(data)
        except (json.JSONDecodeError, SummarizationError) as exc:
            if attempt >= max_retries:
                print(f"Skipping item after invalid JSON: {exc}", file=sys.stderr)
                return None
        except Exception as exc:  # noqa: BLE001 - surface errors during run
            print(f"OpenAI request failed: {exc}", file=sys.stderr)
            return None

    return None
