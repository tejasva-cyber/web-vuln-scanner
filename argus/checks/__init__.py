"""Registry of available checks.

Adding a detection module is a two-line change: import its class and drop it in
``_REGISTRY``. Everything downstream (CLI ``--checks`` list, the engine, the
help text) is generated from this one source of truth.
"""
from __future__ import annotations

from argus.checks.base import Check, InjectionCheck, TargetCheck
from argus.checks.command_injection import CommandInjectionCheck
from argus.checks.csrf import CsrfCheck
from argus.checks.open_redirect import OpenRedirectCheck
from argus.checks.path_traversal import PathTraversalCheck
from argus.checks.security_headers import SecurityHeadersCheck
from argus.checks.sensitive_files import SensitiveFilesCheck
from argus.checks.sql_injection import SqlInjectionCheck
from argus.checks.xss import XssCheck

# Order here is the order findings are produced in — roughly most to least severe.
_REGISTRY: tuple[type[Check], ...] = (
    SqlInjectionCheck,
    CommandInjectionCheck,
    PathTraversalCheck,
    XssCheck,
    OpenRedirectCheck,
    CsrfCheck,
    SensitiveFilesCheck,
    SecurityHeadersCheck,
)


def available() -> dict[str, str]:
    """Map of ``check id -> human description`` for help output."""
    return {c.id: c.description for c in _REGISTRY}


def build(enabled: set[str] | None) -> list[Check]:
    """Instantiate the enabled checks (all of them when ``enabled`` is None)."""
    return [c() for c in _REGISTRY if enabled is None or c.id in enabled]


def known_ids() -> set[str]:
    return {c.id for c in _REGISTRY}


__all__ = [
    "Check", "InjectionCheck", "TargetCheck",
    "available", "build", "known_ids",
]
