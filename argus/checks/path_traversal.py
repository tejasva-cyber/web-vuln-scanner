"""Path traversal / local file inclusion.

We ask for well-known OS files via ``../`` sequences (and a few common
encodings) and look for their unmistakable contents in the response.
"""
from __future__ import annotations

from argus.checks.base import InjectionCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, InjectionPoint, Severity
from argus.payloads import PATH_TRAVERSAL_PAYLOADS, PATH_TRAVERSAL_SIGNATURES

_REFERENCES = ("https://owasp.org/www-community/attacks/Path_Traversal",)


class PathTraversalCheck(InjectionCheck):
    id = "lfi"
    name = "Path Traversal / Local File Inclusion"
    description = "Reads OS files through directory traversal in parameters."

    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = self._send(point, self._baseline_value(point), client)
        baseline_text = baseline.text if baseline else ""

        for payload in PATH_TRAVERSAL_PAYLOADS:
            resp = self._send(point, payload, client)
            if resp is None:
                continue
            for rx in PATH_TRAVERSAL_SIGNATURES:
                match = rx.search(resp.text)
                # Signature must be *new* — some pages legitimately contain the
                # word "extensions", so require it to be absent from baseline.
                if match and not rx.search(baseline_text):
                    return [Finding(
                        check=self.id, title=self.name, severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN, url=point.url,
                        parameter=point.param, payload=payload, method=point.method,
                        description=("A parameter is used to build a filesystem path "
                                     "without normalisation, allowing arbitrary file reads."),
                        evidence=f"System file contents leaked: {match.group(0)[:80]!r}",
                        remediation=("Resolve the canonical path and confirm it stays "
                                     "within an allow-listed base directory; reject any "
                                     "input containing path separators or '..'."),
                        cwe="CWE-22", references=_REFERENCES,
                    )]
        return []
