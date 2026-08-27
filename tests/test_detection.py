"""Detection-logic tests.

These run offline: no sockets, no demo app. Signature matching is tested
directly, and the injection checks are driven against a tiny fake HTTP client
so we can assert on their verdicts deterministically.
"""
from __future__ import annotations

from argus.checks.base import text_similarity
from argus.checks.sql_injection import SqlInjectionCheck
from argus.checks.xss import XssCheck
from argus.models import InjectionPoint
from argus.payloads import (
    PATH_TRAVERSAL_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    command_injection_payloads,
)


# --- fakes ------------------------------------------------------------------
class FakeResponse:
    def __init__(self, text="", status=200, content_type="text/html", location=None):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        if location is not None:
            self.headers["Location"] = location

    @property
    def is_redirect(self):
        return 300 <= self.status_code < 400


class FakeClient:
    """Routes requests to a supplied handler ``fn(method, url, value) -> text``."""

    def __init__(self, fn):
        self._fn = fn

    def get(self, url, *, params=None, allow_redirects=True):
        value = next(iter((params or {}).values()), "")
        return self._fn("GET", url, value)

    def post(self, url, *, data=None, allow_redirects=True):
        value = next(iter((data or {}).values()), "")
        return self._fn("POST", url, value)


def _point(param="q"):
    return InjectionPoint(url="http://t/", method="GET", param=param,
                          base_params={param: "seed"}, source="query")


# --- signature tests --------------------------------------------------------
def test_mysql_error_is_fingerprinted():
    err = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    hits = [engine for engine, rx in SQL_ERROR_SIGNATURES if rx.search(err)]
    assert "MySQL" in hits


def test_benign_text_has_no_sql_signature():
    assert not any(rx.search("Welcome to my perfectly normal blog.")
                   for _, rx in SQL_ERROR_SIGNATURES)


def test_path_traversal_signatures():
    assert any(rx.search("root:x:0:0:root:/root:/bin/bash") for rx in PATH_TRAVERSAL_SIGNATURES)
    assert any(rx.search("[extensions]\r\nmci=1") for rx in PATH_TRAVERSAL_SIGNATURES)


def test_command_injection_payloads_scale():
    assert "; sleep 7" in command_injection_payloads(7)
    assert "; sleep 3" in command_injection_payloads(3)


def test_text_similarity_bounds():
    assert text_similarity("abcdef", "abcdef") == 1.0
    assert text_similarity("the quick brown fox", "") < 0.1


# --- check-level tests ------------------------------------------------------
def test_xss_flags_unencoded_reflection():
    # Server echoes the parameter straight back into HTML.
    check = XssCheck()
    findings = check.check_point(_point(), FakeClient(lambda m, u, v: FakeResponse(f"<p>{v}</p>")))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"


def test_xss_ignores_encoded_reflection():
    # Server HTML-encodes the angle brackets: not exploitable, must not flag.
    def handler(method, url, value):
        safe = value.replace("<", "&lt;").replace(">", "&gt;")
        return FakeResponse(f"<p>{safe}</p>")
    assert XssCheck().check_point(_point(), FakeClient(handler)) == []


def test_xss_ignores_non_html_reflection():
    # Reflection into a JSON API isn't a browser XSS.
    handler = lambda m, u, v: FakeResponse(f'{{"q":"{v}"}}', content_type="application/json")
    assert XssCheck().check_point(_point(), FakeClient(handler)) == []


def test_sqli_error_based_detects_injected_quote():
    def handler(method, url, value):
        if "'" in value:
            return FakeResponse("Warning: mysqli_query(): check the manual that "
                                "corresponds to your MySQL server version")
        return FakeResponse("<p>ok</p>")
    findings = SqlInjectionCheck().check_point(_point(), FakeClient(handler))
    assert len(findings) == 1 and findings[0].cwe == "CWE-89"


def test_sqli_quiet_when_input_is_handled():
    # Same page regardless of input -> nothing to report.
    handler = lambda m, u, v: FakeResponse("<p>stable page</p>")
    assert SqlInjectionCheck().check_point(_point(), FakeClient(handler)) == []
