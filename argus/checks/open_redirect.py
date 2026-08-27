"""Open redirect.

Feed each parameter a URL pointing at a host we obviously don't own and see
whether the server hands back a 3xx that sends the browser there. Redirects are
inspected without following them, so nothing actually leaves for the canary.
"""
from __future__ import annotations

from urllib.parse import urlparse

from argus.checks.base import InjectionCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, InjectionPoint, Severity
from argus.payloads import OPEN_REDIRECT_CANARY, OPEN_REDIRECT_PAYLOADS

_REFERENCES = ("https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",)


class OpenRedirectCheck(InjectionCheck):
    id = "redirect"
    name = "Open Redirect"
    description = "Parameter controls the target of an HTTP redirect."

    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        for payload in OPEN_REDIRECT_PAYLOADS:
            resp = self._send(point, payload, client, allow_redirects=False)
            if resp is None or not (300 <= resp.status_code < 400):
                continue
            location = resp.headers.get("Location", "")
            # Browsers treat backslashes in a URL as forward slashes; normalise
            # so "/\canary" is judged the way a browser would.
            host = urlparse(location.replace("\\", "/")).netloc.lower()
            if OPEN_REDIRECT_CANARY in host:
                return [Finding(
                    check=self.id, title=self.name, severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN, url=point.url,
                    parameter=point.param, payload=payload, method=point.method,
                    description=("A redirect target is taken from user input without "
                                 "validation, enabling phishing and OAuth token theft."),
                    evidence=f"HTTP {resp.status_code} redirected to attacker host: {location}",
                    remediation=("Redirect only to a server-side allow-list of paths, or "
                                 "map an opaque token to the destination. Never redirect "
                                 "to a raw user-supplied URL."),
                    cwe="CWE-601", references=_REFERENCES,
                )]
        return []
