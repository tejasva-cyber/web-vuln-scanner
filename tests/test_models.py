"""Model / aggregation tests (offline)."""
from __future__ import annotations

from argus.models import (
    Confidence,
    Finding,
    InjectionPoint,
    ScanResult,
    Severity,
)


def _finding(title="X", severity=Severity.LOW, confidence=Confidence.FIRM,
             url="http://t/", check="c", parameter=None):
    return Finding(check=check, title=title, severity=severity, confidence=confidence,
                   url=url, description="", parameter=parameter)


def test_dedup_keeps_distinct_titles_on_one_url():
    # Regression: three missing-header findings share (check, url, param, method)
    # and must NOT collapse into one just because the URL matches.
    result = ScanResult(findings=[
        _finding(title="Missing Header: CSP", check="headers"),
        _finding(title="Missing Header: HSTS", check="headers"),
        _finding(title="Missing Header: X-Frame-Options", check="headers"),
    ])
    result.dedup()
    assert len(result.findings) == 3


def test_dedup_collapses_true_duplicates_keeping_higher_confidence():
    result = ScanResult(findings=[
        _finding(confidence=Confidence.TENTATIVE),
        _finding(confidence=Confidence.CERTAIN),
    ])
    result.dedup()
    assert len(result.findings) == 1
    assert result.findings[0].confidence == Confidence.CERTAIN


def test_dedup_sorts_by_severity_then_confidence():
    result = ScanResult(findings=[
        _finding(title="low", severity=Severity.LOW),
        _finding(title="crit", severity=Severity.CRITICAL),
        _finding(title="med", severity=Severity.MEDIUM),
    ])
    result.dedup()
    assert [f.severity for f in result.findings] == [
        Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_counts_by_severity():
    result = ScanResult(findings=[
        _finding(title="a", severity=Severity.HIGH),
        _finding(title="b", severity=Severity.HIGH),
        _finding(title="c", severity=Severity.INFO),
    ])
    counts = result.counts_by_severity()
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.INFO] == 1
    assert counts[Severity.CRITICAL] == 0


def test_injection_point_payload_params_is_non_mutating():
    point = InjectionPoint(url="http://t/", method="GET", param="id",
                           base_params={"id": "1", "page": "2"}, source="query")
    payload = point.payload_params("' OR 1=1")
    assert payload["id"] == "' OR 1=1"
    assert payload["page"] == "2"
    # The original baseline must be untouched for the next probe.
    assert point.base_params["id"] == "1"
