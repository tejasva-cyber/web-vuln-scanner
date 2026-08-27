"""OS command injection — time-based (blind) detection.

Reflection-based command injection is fragile: output may be swallowed. Timing
is not. We inject a command that sleeps for N seconds; if the response is
delayed by ~N, something ran our command. A second, longer probe confirms the
delay scales with the payload and isn't just a slow endpoint.

Note: the sleep only fires when the target *is* vulnerable, so scanning a clean
parameter costs a few fast requests — the time penalty is paid only on a hit.
"""
from __future__ import annotations

from argus.checks.base import InjectionCheck
from argus.http_client import HttpClient
from argus.models import Confidence, Finding, InjectionPoint, Severity
from argus.payloads import command_injection_payloads

_REFERENCES = ("https://owasp.org/www-community/attacks/Command_Injection",)


class CommandInjectionCheck(InjectionCheck):
    id = "cmdi"
    name = "OS Command Injection"
    description = "Time-based blind OS command injection in parameters."

    _PROBE_DELAY = 5
    _CONFIRM_DELAY = 9

    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        base_val = self._baseline_value(point)
        baseline = self._send(point, base_val, client)
        if baseline is None:
            return []
        baseline_time = baseline.elapsed.total_seconds()

        probes = command_injection_payloads(self._PROBE_DELAY)
        confirms = command_injection_payloads(self._CONFIRM_DELAY)
        for probe, confirm in zip(probes, confirms):
            elapsed = self._time(point, base_val + probe, client)
            if elapsed is None:
                continue
            # First hurdle: response took roughly the injected delay and is well
            # above what the endpoint did with a benign value.
            if elapsed >= self._PROBE_DELAY - 1 and elapsed > baseline_time + (self._PROBE_DELAY - 2):
                confirmed = self._time(point, base_val + confirm, client)
                if confirmed is not None and confirmed >= self._CONFIRM_DELAY - 1 and confirmed > elapsed + 2:
                    return [Finding(
                        check=self.id, title=self.name, severity=Severity.CRITICAL,
                        confidence=Confidence.CERTAIN, url=point.url,
                        parameter=point.param, payload=probe, method=point.method,
                        description=("A parameter is passed to an OS shell. Injected "
                                     "commands execute on the server."),
                        evidence=(f"Injected delay tracked the payload: {elapsed:.1f}s "
                                  f"then {confirmed:.1f}s (baseline {baseline_time:.1f}s)"),
                        remediation=("Avoid shells entirely: call binaries via an argv "
                                     "array with no shell interpolation. If a shell is "
                                     "unavoidable, strictly allow-list arguments."),
                        cwe="CWE-78", references=_REFERENCES,
                    )]
        return []

    def _time(self, point, value, client) -> float | None:
        resp = self._send(point, value, client)
        return None if resp is None else resp.elapsed.total_seconds()
