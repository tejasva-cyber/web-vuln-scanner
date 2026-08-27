"""Missing anti-CSRF token detection (heuristic).

A state-changing form (``method=POST``) that carries no unpredictable token is
a candidate for cross-site request forgery. This is a heuristic — the token
could live in a header set by JS, or the endpoint could rely on SameSite
cookies — so findings are reported as tentative and worth a manual glance.
"""
from __future__ import annotations

import re

from argus.checks.base import TargetCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, Form, Severity

# Field names that indicate an anti-CSRF token is present.
_TOKEN_HINT = re.compile(r"csrf|xsrf|_token|nonce|authenticity|verification", re.IGNORECASE)
_REFERENCES = ("https://owasp.org/www-community/attacks/csrf",)


class CsrfCheck(TargetCheck):
    id = "csrf"
    name = "Missing Anti-CSRF Token"
    description = "State-changing forms without an unpredictable token field."

    def check_target(self, url: str, forms: list[Form], client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for form in forms:
            if form.method != "POST" or form.action in seen:
                continue
            seen.add(form.action)
            if any(_TOKEN_HINT.search(name) for name in form.param_names):
                continue
            findings.append(Finding(
                check=self.id, title=self.name, severity=Severity.MEDIUM,
                confidence=Confidence.TENTATIVE, url=form.action, method="POST",
                description=("A form that changes server state has no detectable "
                             "anti-CSRF token among its fields."),
                evidence=f"POST form (fields: {', '.join(form.param_names) or 'none'}) "
                         f"found on {form.source_url}",
                remediation=("Issue a per-session (or per-request) CSRF token and verify "
                             "it server-side. Set SameSite=Lax/Strict on session cookies "
                             "as defence in depth."),
                cwe="CWE-352", references=_REFERENCES,
            ))
        return findings
