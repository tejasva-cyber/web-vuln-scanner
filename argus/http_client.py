"""The single choke point for every outbound request.

Centralising HTTP here buys three things that matter for a scanner:

* **Politeness / safety** — one global rate limiter, so bumping ``--threads``
  never turns the tool into an accidental stress test.
* **Resilience** — connection errors and 5xx blips are retried with backoff
  instead of aborting a check.
* **Honesty** — request accounting, a real User-Agent, and opt-in TLS
  verification. Nothing happens over the wire that isn't counted here.
"""
from __future__ import annotations

import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from argus.config import ScanConfig


class HttpClient:
def __init__(self, config: ScanConfig):
    self._cfg = config
    self._local = threading.local()

        # Rate limiting shared across worker threads. The lock is held *through*
        # the sleep so the configured delay is the spacing between requests
        # globally, not per-thread.
        self._throttle_lock = threading.Lock()
        self._next_allowed = 0.0

        self._count_lock = threading.Lock()
        self._count = 0

    @staticmethod
    def _build_session(cfg: ScanConfig) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": cfg.user_agent, "Accept": "*/*"})
        session.headers.update(cfg.headers)
        if cfg.cookies:
            session.cookies.update(cfg.cookies)
        if cfg.proxy:
            session.proxies.update({"http": cfg.proxy, "https": cfg.proxy})

        # Retry idempotent-ish requests on transient failures. We keep GET/POST
        # both retryable because a scanner's POSTs are probes, not real writes.
        retry = Retry(
            total=cfg.retries,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST", "HEAD"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=max(10, cfg.threads))
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if not cfg.verify_tls:
            session.verify = False
            # Silence the (correct, but here-intentional) warning spam.
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        return session

    # -- rate limiting ----------------------------------------------------
    def _throttle(self) -> None:
        if self._cfg.delay <= 0:
            return
        with self._throttle_lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                time.sleep(wait)
            self._next_allowed = time.monotonic() + self._cfg.delay

    # -- core -------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        allow_redirects: bool = True,
    ) -> requests.Response | None:
        """Send a request, returning the response or ``None`` on network error.

        Checks are written to treat ``None`` as "couldn't test this", so a flaky
        endpoint degrades one probe instead of crashing the scan.
        """
        self._throttle()
        with self._count_lock:
            self._count += 1
        try:
            return self._session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                timeout=self._cfg.timeout,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException:
            return None

    def get(self, url, *, params=None, allow_redirects=True):
        return self.request("GET", url, params=params, allow_redirects=allow_redirects)

    def post(self, url, *, data=None, allow_redirects=True):
        return self.request("POST", url, data=data, allow_redirects=allow_redirects)

    @property
    def request_count(self) -> int:
        with self._count_lock:
            return self._count

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
