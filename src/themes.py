"""Theme extraction for the daily digest."""

from __future__ import annotations

import json
import sys
from typing import Any

from openai import OpenAI

from src.summarise import DEFAULT_MODEL

_REQUIRED_KEYS = {"themes", "one_line_rant"}


class ThemesError(ValueError):
    """Raised when theme output cannot be normalized."""


def _build_prompt(items: list[dict]) -> str:
    titles = "\n".join(f"- {item.get('title', '').strip()}" for item in items)
    tags = ", ".join(
        sorted({tag for item in items for tag in (item.get("tags") or []) if isinstance(tag, str)})
    )
    return (
        "You are summarizing today's threat digest themes for beginners. "
        "Return STRICT JSON with the required keys only.\n\n"
        "Schema:\n"
        "{\n"
        "  \"themes\": [\"short beginner-friendly theme\", \"...\"],\n"
        "  \"one_line_rant\": \"short, safe, mildly sarcastic but clear\"\n"
        "}\n\n"
        "Rules:\n"
        "- Output valid JSON only. No markdown.\n"
        "- Themes must be understandable to a beginner.\n"
        "- Keep one_line_rant short and professional.\n\n"
        f"Titles:\n{titles}\n\n"
        f"Tags: {tags}\n"
    )


def _normalize_output(data: dict[str, Any]) -> dict[str, Any]:
    if not _REQUIRED_KEYS.issubset(data.keys()):
        missing = ", ".join(sorted(_REQUIRED_KEYS - set(data.keys())))
        raise ThemesError(f"Missing keys: {missing}")

    themes = [str(item).strip() for item in data.get("themes", []) if str(item).strip()]
    if not themes:
        raise ThemesError("themes must not be empty")

    return {
        "themes": themes[:4],
        "one_line_rant": str(data.get("one_line_rant", "")).strip(),
    }


def generate_themes(
    items: list[dict],
    api_key: str,
    model: str | None = None,
) -> dict[str, Any] | None:
    if not items:
        return None

    client = OpenAI(api_key=api_key)
    prompt = _build_prompt(items)

    try:
        response = client.chat.completions.create(
            model=model or DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "Return only strict JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=250,
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
