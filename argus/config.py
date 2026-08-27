"""Runtime configuration.

One dataclass holds every knob the CLI can turn. Passing this object around
(rather than a fistful of positional arguments) keeps signatures short and
makes it obvious where a setting is actually used.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# A polite, honest User-Agent. Announcing yourself is both good manners and, in
# an authorised engagement, exactly what the blue team wants to see in the logs.
DEFAULT_USER_AGENT = "Argus/0.4.1 (+https://github.com/tejasva/argus)"


@dataclass
class ScanConfig:
    targets: list[str]
    crawl: bool = False
    max_depth: int = 2
    max_pages: int = 60
    threads: int = 10
    delay: float = 0.0                       # seconds between requests (per client)
    timeout: float = 10.0
    retries: int = 2
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    verify_tls: bool = True
    enabled_checks: set[str] | None = None   # None means "run everything"
    verbose: bool = False
    no_color: bool = False
    output_json: str | None = None
    output_html: str | None = None

    def wants(self, check_id: str) -> bool:
        return self.enabled_checks is None or check_id in self.enabled_checks
