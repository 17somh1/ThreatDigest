"""Digest rendering utilities."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_digest(
    digest_date: str,
    generated_at: str,
    archive_links: list[str],
    template_path: Path,
    editorial: object,
    themes_data: dict | None,
    tone_mode: str,
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)

    return template.render(
        digest_date=digest_date,
        generated_at=generated_at,
        archive_links=archive_links,
        editorial=editorial,
        themes_data=themes_data,
        tone_mode=tone_mode,
    )
