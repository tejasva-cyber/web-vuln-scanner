"""Sensitive file / directory exposure.

Probes a curated list of files that should never be reachable from the web root
(VCS metadata, environment files, backups). A soft-404 baseline is captured
first so sites that answer ``200 OK`` for everything don't produce a wall of
false positives.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from argus.checks.base import TargetCheck, text_similarity
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, Form, Severity
from argus.payloads import SENSITIVE_PATHS

# Paths whose exposure tends to mean secrets or source, not just noise.
_HIGH_RISK = ("git", "env", "config", "backup", ".sql", "id_rsa", "credentials")


class SensitiveFilesCheck(TargetCheck):
    id = "exposure"
    name = "Sensitive File Exposure"
    description = "Well-known secret/backup/VCS files reachable in the web root."

    def check_target(self, url: str, forms: list[Form], client: HttpClient) -> list[Finding]:
        parts = urlparse(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        soft_404 = self._soft_404_body(origin, client)

        findings: list[Finding] = []
        for path, signature, why in SENSITIVE_PATHS:
            resp = client.get(origin + path, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text
            # A "200 for everything" server: skip if this looks like its 404 page.
            if soft_404 is not None and text_similarity(soft_404, body) > 0.90:
                continue
            if signature and not re.search(signature, body):
                continue

            severity = Severity.HIGH if any(k in path for k in _HIGH_RISK) else Severity.MEDIUM
            findings.append(Finding(
                check=self.id, title=self.name, severity=severity,
                confidence=Confidence.FIRM, url=origin + path,
                description=why,
                evidence=f"HTTP 200, {len(body)} bytes returned for {path}",
                remediation=("Remove the file from the document root and block access to "
                             "dot-directories/backup extensions at the web-server layer."),
                cwe="CWE-538",
            ))
        return findings

    def _soft_404_body(self, origin: str, client: HttpClient) -> str | None:
        resp = client.get(origin + "/argus-nonexistent-a1b2c3d4", allow_redirects=False)
        if resp is not None and resp.status_code == 200:
            return resp.text
        return None
