"""Crawler / HTML-parsing tests (offline)."""
from __future__ import annotations

from argus.crawler import extract, normalize_url, _looks_fetchable

_PAGE = """
<html><body>
  <a href="/about">About</a>
  <a href="search?q=1">Search</a>
  <a href="https://other.example/x">External</a>
  <form action="/login" method="POST">
    <input name="user" type="text">
    <input name="pass" type="password">
    <input name="csrf_token" type="hidden" value="abc">
  </form>
  <form method="get">
    <input name="q">
  </form>
</body></html>
"""


def test_extract_resolves_relative_links():
    links, _ = extract("http://site.tld/docs/", _PAGE)
    assert "http://site.tld/about" in links
    assert "http://site.tld/docs/search?q=1" in links
    assert "https://other.example/x" in links


def test_extract_parses_forms_and_methods():
    _, forms = extract("http://site.tld/", _PAGE)
    login = next(f for f in forms if f.action.endswith("/login"))
    assert login.method == "POST"
    assert set(login.param_names) == {"user", "pass", "csrf_token"}


def test_form_without_action_targets_its_page():
    _, forms = extract("http://site.tld/page", _PAGE)
    getform = next(f for f in forms if f.method == "GET")
    assert getform.action == "http://site.tld/page"
    assert getform.param_names == ["q"]


def test_baseline_params_fills_plausible_values():
    _, forms = extract("http://site.tld/", _PAGE)
    login = next(f for f in forms if f.action.endswith("/login"))
    base = login.baseline_params()
    # Pre-filled hidden value is preserved; empty fields get a stand-in.
    assert base["csrf_token"] == "abc"
    assert base["user"] and base["pass"]


def test_normalize_url_drops_fragment_and_lowercases_host():
    assert normalize_url("HTTP://Site.TLD/a#frag") == "http://site.tld/a"


def test_looks_fetchable_skips_assets():
    assert _looks_fetchable("http://s/page")
    assert not _looks_fetchable("http://s/app.js")
    assert not _looks_fetchable("http://s/logo.PNG")
