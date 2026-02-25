"""Lightweight HTML to text extraction for feed summaries."""

from __future__ import annotations

import html
import re

_TAG_RE = re.compile(r"<[^>]+>")


def extract_text(html_content: str) -> str:
    if not html_content:
        return ""
    stripped = _TAG_RE.sub(" ", html_content)
    unescaped = html.unescape(stripped)
    return " ".join(unescaped.split())
