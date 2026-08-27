"""SQL injection — error-based and boolean-based (blind) detection."""
from __future__ import annotations

from argus.checks.base import InjectionCheck, text_similarity
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, InjectionPoint, Severity
from argus.payloads import (
    SQL_ERROR_SIGNATURES,
    SQLI_BOOLEAN_PAIRS,
    SQLI_ERROR_PAYLOADS,
)

_REFERENCES = ("https://owasp.org/www-community/attacks/SQL_Injection",)


class SqlInjectionCheck(InjectionCheck):
    id = "sqli"
    name = "SQL Injection"
    description = "Error-based and boolean-based SQL injection in parameters."

    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = self._send(point, self._baseline_value(point), client)
        if baseline is None:
            return []

        finding = (self._error_based(point, client, baseline.text)
                   or self._boolean_based(point, client, baseline.text))
        return [finding] if finding else []

    def _error_based(self, point, client, baseline_text) -> Finding | None:
        # Signatures already in the clean response would be false positives, so
        # remember them and ignore those engines.
        pre_existing = {eng for eng, rx in SQL_ERROR_SIGNATURES if rx.search(baseline_text)}
        base_val = self._baseline_value(point)
        for payload in SQLI_ERROR_PAYLOADS:
            resp = self._send(point, base_val + payload, client)
            if resp is None:
                continue
            for engine, rx in SQL_ERROR_SIGNATURES:
                match = rx.search(resp.text)
                if match and engine not in pre_existing:
                    return self._finding(
                        point, payload, Confidence.FIRM,
                        f"{engine} error surfaced: {match.group(0)[:120]!r}",
                    )
        return None

    def _boolean_based(self, point, client, baseline_text) -> Finding | None:
        base_val = self._baseline_value(point)
        for true_clause, false_clause in SQLI_BOOLEAN_PAIRS:
            r_true = self._send(point, base_val + true_clause, client)
            r_false = self._send(point, base_val + false_clause, client)
            if r_true is None or r_false is None:
                continue
            sim_true = text_similarity(baseline_text, r_true.text)
            sim_false = text_similarity(baseline_text, r_false.text)
            # A genuine injection keeps the "always true" page intact while the
            # "always false" page collapses (empty result set / different view).
            if sim_true > 0.95 and (sim_true - sim_false) > 0.10:
                return self._finding(
                    point, f"{true_clause!r} vs {false_clause!r}", Confidence.FIRM,
                    f"Boolean condition changed the response "
                    f"(true≈{sim_true:.2f}, false≈{sim_false:.2f} vs baseline)",
                )
        return None

    def _finding(self, point, payload, confidence, evidence) -> Finding:
        return Finding(
            check=self.id, title=self.name, severity=Severity.HIGH,
            confidence=confidence, url=point.url, parameter=point.param,
            payload=payload, method=point.method,
            description=("A parameter appears to be concatenated into a SQL query "
                         "without parameterisation."),
            evidence=evidence,
            remediation=("Use parameterised queries / prepared statements. Bind all "
                         "user input; never build SQL by string concatenation."),
            cwe="CWE-89", references=_REFERENCES,
        )
