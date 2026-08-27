"""Core data model.

Everything Argus discovers or reports is one of a handful of small, immutable
value objects defined here. Keeping them in one place means the crawler, the
checks and the reporter all speak the same language and nothing has to guess at
dict keys.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable
from urllib.parse import urlencode


class Severity(IntEnum):
    """CVSS-flavoured severity buckets, ordered so findings sort naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


class Confidence(IntEnum):
    """How sure the check is. Tentative findings are worth a manual look;
    certain ones the scanner is willing to stake its reputation on."""

    TENTATIVE = 0
    FIRM = 1
    CERTAIN = 2

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class Finding:
    """A single reported issue. Frozen so it can live in a set for de-duping."""

    check: str                       # short id of the check, e.g. "sqli"
    title: str
    severity: Severity
    confidence: Confidence
    url: str
    description: str
    evidence: str = ""               # the concrete proof (error string, timing, ...)
    parameter: str | None = None
    payload: str | None = None
    method: str = "GET"
    remediation: str = ""
    cwe: str | None = None           # e.g. "CWE-89"
    references: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> tuple:
        """Two findings with the same fingerprint are the same issue reported
        twice (e.g. the crawler hit the endpoint from two pages). Title is part
        of the key so distinct issues on one URL — say three missing headers —
        don't collapse into one."""
        return (self.check, self.title, self.url, self.parameter, self.method)


@dataclass
class InputField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    """An HTML ``<form>`` reduced to the parts a scanner cares about."""

    action: str                      # absolute URL the form submits to
    method: str = "GET"
    inputs: list[InputField] = field(default_factory=list)
    source_url: str = ""             # page the form was found on

    @property
    def param_names(self) -> list[str]:
        return [i.name for i in self.inputs if i.name]

    def baseline_params(self) -> dict[str, str]:
        """Sensible default values so a submitted form looks plausible rather
        than empty (some apps only reach the vulnerable code path when every
        field is filled in)."""
        out: dict[str, str] = {}
        for i in self.inputs:
            if not i.name:
                continue
            if i.value:
                out[i.name] = i.value
            elif i.type == "email":
                out[i.name] = "argus@example.com"
            elif i.type in ("number", "tel"):
                out[i.name] = "1"
            else:
                out[i.name] = "argus"
        return out


@dataclass
class InjectionPoint:
    """A single place a payload can be injected.

    Unifying query parameters and form fields behind one object is what lets a
    check stay blissfully unaware of *where* its parameter came from — it just
    asks for a request with one value swapped out.
    """

    url: str                         # base URL (GET) or form action
    method: str                      # "GET" or "POST"
    param: str                       # the parameter under test
    base_params: dict[str, str]      # every other param at its baseline value
    source: str = "query"            # "query" or "form", for reporting

    def payload_params(self, value: str) -> dict[str, str]:
        params = dict(self.base_params)
        params[self.param] = value
        return params

    def location(self) -> str:
        """Human-readable "where", used in log lines and reports."""
        if self.method == "GET" and self.base_params:
            return f"{self.url}?{urlencode(self.base_params)}"
        return self.url


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    injection_points: int = 0
    urls_crawled: int = 0
    requests_sent: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def add(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def dedup(self) -> None:
        """Collapse duplicate findings, keeping the highest-confidence copy."""
        best: dict[tuple, Finding] = {}
        for f in self.findings:
            current = best.get(f.fingerprint)
            if current is None or f.confidence > current.confidence:
                best[f.fingerprint] = f
        self.findings = sorted(
            best.values(),
            key=lambda f: (f.severity, f.confidence),
            reverse=True,
        )

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
