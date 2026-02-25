"""OpenAI summarization with strict JSON output."""

from __future__ import annotations

import json
import sys
from typing import Any

from openai import OpenAI

from src.extract import extract_text

DEFAULT_MODEL = "gpt-4o-mini"

_ALLOWED_ATTACK_STAGES = {
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unknown",
}

_REQUIRED_KEYS = {
    "risk",
    "confidence",
    "spicy_take",
    "tl_dr",
    "what_happened",
    "why_it_matters",
    "beginner_breakdown",
    "attack_stage",
    "soc_focus",
    "tags",
    "recommended_actions",
}


class SummarizationError(ValueError):
    """Raised when model output cannot be normalized."""


def _build_prompt(item: dict, tone_mode: str) -> str:
    summary_text = extract_text(item.get("summary", ""))
    tone_hint = (
        "Use a mild, professional sarcasm in spicy_take." if tone_mode == "spicy" else
        "Use a plain Analyst take that starts with 'Analyst take:' and contains no sarcasm."
    )

    return (
        "You are a senior SOC analyst writing a threat digest for people new to threat intel. "
        "Be engaging but always clear and factual.\n"
        f"Tone rule: {tone_hint}\n\n"
        "Return STRICT JSON with the required keys only.\n\n"
        "Schema:\n"
        "{\n"
        "  \"risk\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"confidence\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"spicy_take\": \"1 sentence, slightly sarcastic but professional; must not be confusing\",\n"
        "  \"tl_dr\": \"1 sentence, plain English\",\n"
        "  \"what_happened\": \"2-4 sentences, factual\",\n"
        "  \"why_it_matters\": \"2-4 sentences, practical impact\",\n"
        "  \"beginner_breakdown\": [\"TERM - definition\", \"TERM - definition\"],\n"
        "  \"attack_stage\": \"Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact|Unknown\",\n"
        "  \"soc_focus\": [\"2-4 concrete detection/response ideas, plain English\"],\n"
        "  \"tags\": [\"ransomware\", \"cve\", \"cloud\"],\n"
        "  \"recommended_actions\": [\"max 3 actions, imperative voice\"]\n"
        "}\n\n"
        "Rules:\n"
        "- Output valid JSON only. No markdown.\n"
        "- Define any jargon used in beginner_breakdown.\n"
        "- If source content is insufficient, set confidence LOW and say what is unclear.\n"
        "- Do not invent facts.\n\n"
        "Item:\n"
        f"Title: {item.get('title', '').strip()}\n"
        f"Source: {item.get('source', '').strip()}\n"
        f"Published: {item.get('published', '').strip()}\n"
        f"URL: {item.get('url', '').strip()}\n"
        f"Summary: {summary_text}\n"
    )


def _normalize_output(data: dict[str, Any], tone_mode: str) -> dict[str, Any]:
    if not _REQUIRED_KEYS.issubset(data.keys()):
        missing = ", ".join(sorted(_REQUIRED_KEYS - set(data.keys())))
        raise SummarizationError(f"Missing keys: {missing}")

    risk = str(data.get("risk", "")).upper()
    confidence = str(data.get("confidence", "")).upper()
    if risk not in {"LOW", "MEDIUM", "HIGH"}:
        raise SummarizationError("Invalid risk value")
    if confidence not in {"LOW", "MEDIUM", "HIGH"}:
        raise SummarizationError("Invalid confidence value")

    attack_stage = str(data.get("attack_stage", "")).strip()
    if attack_stage not in _ALLOWED_ATTACK_STAGES:
        raise SummarizationError("Invalid attack_stage value")

    def _list(value: Any) -> list[str]:
        return [str(item).strip() for item in (value or []) if str(item).strip()]

    beginner_breakdown = _list(data.get("beginner_breakdown"))
    soc_focus = _list(data.get("soc_focus"))
    tags = _list(data.get("tags"))
    recommended_actions = _list(data.get("recommended_actions"))

    if not beginner_breakdown:
        raise SummarizationError("beginner_breakdown must not be empty")
    if not soc_focus:
        raise SummarizationError("soc_focus must not be empty")

    spicy_take = str(data.get("spicy_take", "")).strip()
    if tone_mode != "spicy":
        if not spicy_take.lower().startswith("analyst take"):
            spicy_take = f"Analyst take: {spicy_take}"

    return {
        "risk": risk,
        "confidence": confidence,
        "spicy_take": spicy_take,
        "tl_dr": str(data.get("tl_dr", "")).strip(),
        "what_happened": str(data.get("what_happened", "")).strip(),
        "why_it_matters": str(data.get("why_it_matters", "")).strip(),
        "beginner_breakdown": beginner_breakdown,
        "attack_stage": attack_stage,
        "soc_focus": soc_focus,
        "tags": tags,
        "recommended_actions": recommended_actions[:3],
    }


def summarize_item(
    item: dict,
    api_key: str,
    tone_mode: str = "spicy",
    model: str | None = None,
    max_retries: int = 1,
) -> dict[str, Any] | None:
    client = OpenAI(api_key=api_key)
    prompt = _build_prompt(item, tone_mode=tone_mode)
    attempts = max_retries + 1

    for attempt in range(attempts):
        try:
            response = client.chat.completions.create(
                model=model or DEFAULT_MODEL,
                messages=[
                    {"role": "system", "content": "Return only strict JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3 if tone_mode == "spicy" else 0.2,
                max_tokens=700,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content or ""
            data = json.loads(content)
            return _normalize_output(data, tone_mode=tone_mode)
        except (json.JSONDecodeError, SummarizationError) as exc:
            if attempt >= max_retries:
                print(f"Skipping item after invalid JSON: {exc}", file=sys.stderr)
                return None
        except Exception as exc:  # noqa: BLE001 - surface errors during run
            print(f"OpenAI request failed: {exc}", file=sys.stderr)
            return None

    return None
