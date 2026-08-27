"""Discovery: turn one or more seed URLs into a map of testable inputs.

HTML parsing is done with the standard library's ``html.parser`` rather than a
third-party library. It keeps the dependency footprint to a single package
(``requests``) and it's more than enough to pull links and forms out of a page.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

from argus.http_client import HttpClient
from argus.models import Form, InputField

# Extensions that are never worth fetching in a crawl — binary assets and media
# that won't contain links or forms.
_SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
)


class _LinkFormParser(HTMLParser):
    """Collects anchor targets and forms in one pass over the document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "a":
            href = a.get("href", "").strip()
            if href:
                self.links.append(href)
        elif tag == "form":
            self._form = Form(action=a.get("action", ""),
                              method=(a.get("method") or "GET").upper())
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            name = a.get("name", "").strip()
            if name:
                self._form.inputs.append(
                    InputField(name=name, type=a.get("type", "text"), value=a.get("value", ""))
                )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # <input ... /> — treat the same as an open tag; inputs are void anyway.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def normalize_url(url: str) -> str:
    """Drop fragments and lower-case the scheme/host so the same page isn't
    crawled twice under two spellings."""
    url, _ = urldefrag(url)
    parts = urlparse(url)
    netloc = parts.netloc.lower()
    scheme = parts.scheme.lower()
    return urlunparse((scheme, netloc, parts.path or "/", parts.params, parts.query, ""))


def extract(base_url: str, html: str) -> tuple[list[str], list[Form]]:
    """Parse a page, returning absolute links and forms with absolute actions."""
    parser = _LinkFormParser()
    try:
        parser.feed(html)
    except Exception:
        # A malformed document shouldn't sink the crawl; take what we parsed.
        pass

    links = [normalize_url(urljoin(base_url, href)) for href in parser.links]

    forms: list[Form] = []
    for form in parser.forms:
        form.action = normalize_url(urljoin(base_url, form.action)) if form.action else normalize_url(base_url)
        form.source_url = base_url
        forms.append(form)
    return links, forms


def _looks_fetchable(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith(_SKIP_EXTENSIONS)


class Crawler:
    """Breadth-first, same-origin crawler bounded by depth and page count."""

    def __init__(self, client: HttpClient, max_depth: int, max_pages: int,
                 on_visit=None):
        self._client = client
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._on_visit = on_visit  # optional callback(url) for progress output

    def crawl(self, seeds: list[str]) -> tuple[set[str], list[Form]]:
        allowed_hosts = {urlparse(s).netloc.lower() for s in seeds}
        queue: deque[tuple[str, int]] = deque((normalize_url(s), 0) for s in seeds)
        visited: set[str] = set()
        discovered: set[str] = set(normalize_url(s) for s in seeds)
        forms: list[Form] = []

        while queue and len(visited) < self._max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            if self._on_visit:
                self._on_visit(url)

            resp = self._client.get(url)
            if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
                continue

            links, page_forms = extract(url, resp.text)
            forms.extend(page_forms)

            for link in links:
                if urlparse(link).netloc.lower() not in allowed_hosts:
                    continue
                discovered.add(link)
                if (depth + 1 <= self._max_depth and link not in visited
                        and _looks_fetchable(link)):
                    queue.append((link, depth + 1))

        return discovered, forms
