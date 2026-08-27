"""Reflected cross-site scripting.

Strategy: inject a uniquely-tagged payload whose value depends on HTML
metacharacters (``<``, ``>``, ``"``) surviving intact. If the exact payload
comes back verbatim in an HTML response, the app failed to encode output and a
script context is reachable.
"""
from __future__ import annotations

import uuid

from argus.checks.base import InjectionCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, InjectionPoint, Severity
from argus.payloads import XSS_PROBES

_REFERENCES = ("https://owasp.org/www-community/attacks/xss/",)


class XssCheck(InjectionCheck):
    id = "xss"
    name = "Reflected Cross-Site Scripting"
    description = "Un-encoded reflection of request parameters into HTML."

    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        # A per-parameter token so we never match another parameter's echo.
        token = "arg" + uuid.uuid4().hex[:7]
        for probe in XSS_PROBES:
            payload = probe.format(token=token)
            resp = self._send(point, payload, client)
            if resp is None:
                continue
            if "html" not in resp.headers.get("Content-Type", "").lower():
                continue  # reflection into JSON/plain text isn't a browser XSS
            if payload in resp.text:
                return [Finding(
                    check=self.id, title=self.name, severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN, url=point.url,
                    parameter=point.param, payload=payload, method=point.method,
                    description=("User input is reflected into the HTML response "
                                 "without output encoding."),
                    evidence=f"Payload reflected verbatim (HTML metacharacters intact): {payload!r}",
                    remediation=("Context-aware output encoding (HTML entity-encode "
                                 "by default). Prefer a templating engine that "
                                 "auto-escapes, and add a Content-Security-Policy."),
                    cwe="CWE-79", references=_REFERENCES,
                )]
        return []
