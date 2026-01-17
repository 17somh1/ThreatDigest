"""HTTP fetcher utilities."""

from __future__ import annotations

import urllib.request

DEFAULT_TIMEOUT = 20
USER_AGENT = "ThreatDigest/0.1 (+https://github.com/)"


def fetch_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")
