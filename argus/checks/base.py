"""Base classes for detection modules.

There are two shapes of check and every module is one of them:

* :class:`InjectionCheck` — tests a single parameter (query string or form
  field). The engine hands it one :class:`InjectionPoint` at a time.
* :class:`TargetCheck` — tests a URL as a whole (headers, forms, well-known
  paths). The engine hands it a URL plus any forms found there.

Keeping the two apart lets the engine parallelise the expensive, per-parameter
work without target-level checks getting run once per parameter by accident.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from difflib import SequenceMatcher

from argus.http_client import HttpClient
from argus.models import Finding, Form, InjectionPoint

# Comparing multi-hundred-KB pages char-by-char is pointless; the first slice
# captures the structural differences we care about and keeps diffing cheap.
_SIMILARITY_WINDOW = 20_000


def text_similarity(a: str, b: str) -> float:
    """Ratio in [0, 1] of how alike two response bodies are.

    Used by the differential checks (boolean SQLi) to tell "same page" from
    "the app behaved differently", which is more robust than string matching
    against pages full of timestamps and CSRF tokens.
    """
    return SequenceMatcher(None, a[:_SIMILARITY_WINDOW], b[:_SIMILARITY_WINDOW]).ratio()


class Check(ABC):
    id: str = ""
    name: str = ""
    description: str = ""


class InjectionCheck(Check):
    @abstractmethod
    def check_point(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        ...

    # -- shared plumbing --------------------------------------------------
    def _send(self, point: InjectionPoint, value: str, client: HttpClient,
              *, allow_redirects: bool = True):
        params = point.payload_params(value)
        if point.method == "GET":
            return client.get(point.url, params=params, allow_redirects=allow_redirects)
        return client.post(point.url, data=params, allow_redirects=allow_redirects)

    def _baseline_value(self, point: InjectionPoint) -> str:
        return point.base_params.get(point.param) or "argus"


class TargetCheck(Check):
    @abstractmethod
    def check_target(self, url: str, forms: list[Form], client: HttpClient) -> list[Finding]:
        ...
