"""Passive audit of security response headers, cookie flags and info leakage.

No payloads here — this is a single honest GET and a read of what came back. It
catches the low-effort, high-value hardening gaps that show up on almost every
first-pass assessment.
"""
from __future__ import annotations

from urllib.parse import urlparse

from argus.checks.base import TargetCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, Form, Severity
from argus.payloads import SECURITY_HEADERS

_SEVERITY = {
    "info": Severity.INFO, "low": Severity.LOW,
    "medium": Severity.MEDIUM, "high": Severity.HIGH,
}


class SecurityHeadersCheck(TargetCheck):
    id = "headers"
    name = "Security Headers & Information Disclosure"
    description = "Missing hardening headers, weak cookie flags, version banners."

    def check_target(self, url: str, forms: list[Form], client: HttpClient) -> list[Finding]:
        resp = client.get(url)
        if resp is None:
            return []

        findings: list[Finding] = []
        headers = resp.headers
        is_https = urlparse(url).scheme == "https"
        csp = headers.get("Content-Security-Policy", "").lower()

        # -- missing hardening headers ------------------------------------
        for name, sev, rationale in SECURITY_HEADERS:
            if name == "Strict-Transport-Security" and not is_https:
                continue  # HSTS is meaningless over plaintext
            if name == "X-Frame-Options" and "frame-ancestors" in csp:
                continue  # CSP already covers framing
            if headers.get(name, "").strip():
                continue
            findings.append(self._missing_header(url, name, _SEVERITY[sev], rationale))

        # -- version / technology disclosure ------------------------------
        for banner in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = headers.get(banner, "")
            if value and any(ch.isdigit() for ch in value):
                findings.append(Finding(
                    check=self.id, title="Version Disclosure", severity=Severity.INFO,
                    confidence=Confidence.CERTAIN, url=url,
                    description="A response header advertises the exact software version, "
                                "handing attackers a shortlist of known CVEs.",
                    evidence=f"{banner}: {value}",
                    remediation=f"Suppress or genericise the '{banner}' header.",
                    cwe="CWE-200",
                ))

        findings.extend(self._cookie_findings(url, resp, is_https))
        return findings

    def _missing_header(self, url, name, severity, rationale) -> Finding:
        return Finding(
            check=self.id, title=f"Missing Header: {name}", severity=severity,
            confidence=Confidence.CERTAIN, url=url,
            description=rationale,
            evidence=f"Response did not set '{name}'.",
            remediation=f"Set the '{name}' header on all responses.",
            cwe="CWE-693",
        )

    def _cookie_findings(self, url, resp, is_https) -> list[Finding]:
        try:
            set_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw = resp.headers.get("Set-Cookie")
            set_cookies = [raw] if raw else []

        findings: list[Finding] = []
        for cookie in set_cookies:
            lowered = cookie.lower()
            name = cookie.split("=", 1)[0].strip()
            missing = []
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if is_https and "secure" not in lowered:
                missing.append("Secure")
            if missing:
                findings.append(Finding(
                    check=self.id, title="Insecure Cookie Attributes", severity=Severity.LOW,
                    confidence=Confidence.CERTAIN, url=url,
                    description="A cookie is set without recommended protective attributes.",
                    evidence=f"Cookie '{name}' missing: {', '.join(missing)}",
                    remediation="Set HttpOnly, Secure and SameSite on session cookies.",
                    cwe="CWE-1004",
                ))
        return findings
