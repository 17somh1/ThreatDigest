"""Digest rendering utilities."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_digest(
    items: list[dict],
    digest_date: str,
    generated_at: str,
    archive_links: list[str],
    template_path: Path,
    themes_data: dict | None,
    tone_mode: str,
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)

    grouped = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for item in items:
        grouped.setdefault(item.get("risk", "LOW"), []).append(item)

    sections = [
        ("High", grouped.get("HIGH", [])),
        ("Medium", grouped.get("MEDIUM", [])),
        ("Low", grouped.get("LOW", [])),
    ]

    return template.render(
        digest_date=digest_date,
        generated_at=generated_at,
        sections=sections,
        archive_links=archive_links,
        themes_data=themes_data,
        tone_mode=tone_mode,
    )
