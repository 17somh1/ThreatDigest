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
    "hook",
    "tl_dr",
    "what_happened",
    "why_it_matters",
    "who_should_care",
    "attacker_path",
    "watch_next",
    "beginner_breakdown",
    "attack_stage",
    "soc_focus",
    "tags",
    "recommended_actions",
}


class SummarizationError(ValueError):
    """Raised when model output cannot be normalized."""


def _build_prompt(item: dict) -> str:
    summary_text = extract_text(item.get("summary", ""))

    return (
        "You are a senior SOC analyst writing a daily threat briefing for readers who want "
        "technical depth without mystery jargon. Lead with consequences, stay concrete, and "
        "keep urgency proportional to the evidence.\n\n"
        "Return STRICT JSON with the required keys only.\n\n"
        "Schema:\n"
        "{\n"
        "  \"risk\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"confidence\": \"LOW|MEDIUM|HIGH\",\n"
        "  \"hook\": \"1 sentence, consequence-led; explain why this matters now\",\n"
        "  \"tl_dr\": \"1 sentence, plain English\",\n"
        "  \"what_happened\": \"2-4 sentences, factual\",\n"
        "  \"why_it_matters\": \"2-4 sentences, practical impact\",\n"
        "  \"who_should_care\": \"1 sentence naming the teams, products, or environments most exposed\",\n"
        "  \"attacker_path\": \"1-2 sentences describing how an attacker gains leverage or what abuse looks like\",\n"
        "  \"watch_next\": \"1 sentence on the next signal, vendor action, or follow-on reporting to monitor\",\n"
        "  \"beginner_breakdown\": [\"TERM - definition\", \"TERM - definition\"],\n"
        "  \"attack_stage\": \"Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact|Unknown\",\n"
        "  \"soc_focus\": [\"2-4 concrete detection/response ideas, plain English\"],\n"
        "  \"tags\": [\"ransomware\", \"cve\", \"cloud\"],\n"
        "  \"recommended_actions\": [\"max 3 actions, imperative voice, ordered from most immediate to least immediate\"]\n"
        "}\n\n"
        "Rules:\n"
        "- Output valid JSON only. No markdown.\n"
        "- No sarcasm, jokes, or branded voice.\n"
        "- Define any jargon used in beginner_breakdown.\n"
        "- If source content is insufficient, set confidence LOW and say what is unclear.\n"
        "- If the story is a retrospective, research roundup, or trend report, say that explicitly and do not overstate urgency.\n"
        "- SOC focus must be product/context-specific when possible.\n"
        "- Avoid generic advice like 'educate users' unless the story is explicitly about awareness or phishing behavior.\n"
        "- Do not invent facts.\n\n"
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

    attack_stage = str(data.get("attack_stage", "")).strip()
    if attack_stage not in _ALLOWED_ATTACK_STAGES:
        raise SummarizationError("Invalid attack_stage value")

    def _list(value: Any) -> list[str]:
        return [str(item).strip() for item in (value or []) if str(item).strip()]

    beginner_breakdown = _list(data.get("beginner_breakdown"))
    soc_focus = _list(data.get("soc_focus"))
    tags = _list(data.get("tags"))
    recommended_actions = _list(data.get("recommended_actions"))
    hook = str(data.get("hook", "")).strip()
    who_should_care = str(data.get("who_should_care", "")).strip()
    attacker_path = str(data.get("attacker_path", "")).strip()
    watch_next = str(data.get("watch_next", "")).strip()

    if not beginner_breakdown:
        raise SummarizationError("beginner_breakdown must not be empty")
    if not soc_focus:
        raise SummarizationError("soc_focus must not be empty")
    if not hook:
        raise SummarizationError("hook must not be empty")
    if not who_should_care:
        raise SummarizationError("who_should_care must not be empty")
    if not attacker_path:
        raise SummarizationError("attacker_path must not be empty")
    if not watch_next:
        raise SummarizationError("watch_next must not be empty")

    return {
        "risk": risk,
        "confidence": confidence,
        "hook": hook,
        "tl_dr": str(data.get("tl_dr", "")).strip(),
        "what_happened": str(data.get("what_happened", "")).strip(),
        "why_it_matters": str(data.get("why_it_matters", "")).strip(),
        "who_should_care": who_should_care,
        "attacker_path": attacker_path,
        "watch_next": watch_next,
        "beginner_breakdown": beginner_breakdown,
        "attack_stage": attack_stage,
        "soc_focus": soc_focus,
        "tags": tags,
        "recommended_actions": recommended_actions[:3],
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
                max_tokens=900,
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
