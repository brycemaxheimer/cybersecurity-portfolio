"""Guards between untrusted content and the published page.

Rules:
- Links on the page come only from URLs the collector gathered, checked here.
  Model output never supplies a URL; it refers to items by ID.
- Model text is plain text. URLs inside it are removed, control characters
  stripped, length capped, and the renderer HTML-escapes it.
"""

from __future__ import annotations

import html
import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

# Hosts the collector builds links for itself (not taken from feed items).
BUILTIN_HOSTS = {
    "nvd.nist.gov",
    "www.cisa.gov",
    "github.com",
    "bsky.app",
    "infosec.exchange",
    "www.reddit.com",
    "news.ycombinator.com",
    "msrc.microsoft.com",
    "www.first.org",
}

_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)://\S+|\bwww\.\S+\.\S+")
_CONTROL = {"Cc", "Cf", "Co", "Cs"}


def safe_url(url: str, allowed_hosts: set[str] | frozenset[str] | None = None) -> str | None:
    """Return a normalized https URL, or None if it should not be linked."""
    if not isinstance(url, str) or len(url) > 2048:
        return None
    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None
    if parts.username or parts.password or parts.port not in (None, 443):
        return None
    host = parts.hostname.lower().rstrip(".")
    hosts = BUILTIN_HOSTS if allowed_hosts is None else (set(allowed_hosts) | BUILTIN_HOSTS)
    if host not in hosts:
        return None
    if any(ord(c) < 0x21 or c in "\"'<>\\`" for c in url):
        return None
    return urlunsplit(("https", host, parts.path or "/", parts.query, ""))


def clean_model_text(text: str, max_len: int = 4000) -> str:
    """Make model output safe to show as plain text."""
    if not isinstance(text, str):
        return ""
    text = _URL_IN_TEXT.sub("[link removed]", text)
    text = "".join(
        ch for ch in text if ch in "\n\t" or unicodedata.category(ch) not in _CONTROL
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def has_url(text: str) -> str | None:
    """The first URL-looking run in text, or None. Published model text has been
    through clean_model_text, so a hit means a field was never cleaned."""
    m = _URL_IN_TEXT.search(text or "")
    return m.group(0) if m else None


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "template"):
            self._skip += 1
        elif tag in ("p", "br", "li", "div", "h1", "h2", "h3", "h4", "tr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(markup: str, max_len: int | None = None) -> str:
    """Strip HTML to plain text (feed summaries, Mastodon posts)."""
    if not markup:
        return ""
    p = _TextExtractor()
    try:
        p.feed(markup)
        p.close()
        text = "".join(p.parts)
    except Exception:  # malformed markup: fall back to a crude strip
        text = html.unescape(re.sub(r"<[^>]+>", " ", markup))
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\s*\n\s*", "\n", text).strip()
    if max_len and len(text) > max_len:
        text = text[:max_len].rstrip() + "…"
    return text


def fence(text: str) -> str:
    """Neutralize anything that looks like our untrusted-data delimiters."""
    return re.sub(r"(?i)</?\s*untrusted[^>]*>", "[tag removed]", text or "")
