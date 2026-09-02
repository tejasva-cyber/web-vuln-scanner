"""The scan engine: discovery, fan-out and result aggregation.

The engine is intentionally thin. It decides *what* to test (injection points
and target URLs) and *how much at once* (the thread pool), then delegates the
actual verdicts to the checks. All network I/O funnels through one shared
:class:`HttpClient`, so the rate limiter applies globally no matter how many
worker threads are running.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlparse, urlunparse

from argus import checks
from argus.checks import InjectionCheck, TargetCheck
from argus.config import ScanConfig
from argus.crawler import Crawler, extract, normalize_url
from argus.http_client import HttpClient
from argus.models import Form, InjectionPoint, ScanResult


class _NullReporter:
    """No-op sink so the engine can run head-less (tests, library use)."""

    def __getattr__(self, _name):
        return lambda *a, **k: None


class ScanEngine:
    def __init__(self, config: ScanConfig, reporter=None):
        self.cfg = config
        self.reporter = reporter or _NullReporter()
        active = checks.build(config.enabled_checks)
        self.injection_checks = [c for c in active if isinstance(c, InjectionCheck)]
        self.target_checks = [c for c in active if isinstance(c, TargetCheck)]

    # -- public API -------------------------------------------------------
    def run(self) -> ScanResult:
        result = ScanResult(started_at=time.time())
        with HttpClient(self.cfg) as client:
            discovered, forms = self._discover(client)
            points = self._injection_points(discovered, forms)
            result.urls_crawled = len(discovered)
            result.injection_points = len(points)

            self.reporter.info(
                f"Mapped {len(discovered)} URL(s), {len(forms)} form(s), "
                f"{len(points)} injection point(s)"
            )

            self._run_injection_checks(points, client, result)
            self._run_target_checks(self.cfg.targets, forms, client, result)

            result.requests_sent = client.request_count
        result.finished_at = time.time()
        result.dedup()
        return result

    # -- discovery --------------------------------------------------------
    def _discover(self, client: HttpClient) -> tuple[set[str], list[Form]]:
        if self.cfg.crawl:
            self.reporter.phase("Crawl")
            crawler = Crawler(client, self.cfg.max_depth, self.cfg.max_pages,
                              on_visit=self.reporter.crawl)
            return crawler.crawl(self.cfg.targets)

        # Without crawling we still fetch each seed once to harvest its forms.
        self.reporter.phase("Discover")
        discovered = {normalize_url(s) for s in self.cfg.targets}
        forms: list[Form] = []
        for seed in self.cfg.targets:
            resp = client.get(seed)
            if resp is not None and "html" in resp.headers.get("Content-Type", "").lower():
                _, page_forms = extract(seed, resp.text)
                forms.extend(page_forms)
        return discovered, forms

    def _injection_points(self, discovered: set[str], forms: list[Form]) -> list[InjectionPoint]:
        points: list[InjectionPoint] = []
        seen: set[tuple[str, str, str]] = set()

        def add(method: str, url: str, param: str, base: dict, source: str) -> None:
            key = (method, url, param)
            if key in seen:
                return
            seen.add(key)
            points.append(InjectionPoint(url=url, method=method, param=param,
                                        base_params=dict(base), source=source))

        # GET query-string parameters from every discovered URL.
        for url in discovered:
            parsed = urlparse(url)
            if not parsed.query:
                continue
          params = parse_qsl(parsed.query, keep_blank_values=True)
          base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

for name, _value in params:
    add("GET", base_url, name, params, "query")

        # Form fields, GET or POST.
        for form in forms:
            base = form.baseline_params()
            for name in form.param_names:
                add(form.method, form.action, name, base, "form")

        return points

    # -- execution --------------------------------------------------------
    def _run_injection_checks(self, points, client, result: ScanResult) -> None:
        if not points or not self.injection_checks:
            return
        self.reporter.phase("Active checks")
        tasks = [(check, point) for point in points for check in self.injection_checks]
        self._fan_out(tasks, lambda t: t[0].check_point(t[1], client),
                      label=lambda t: f"{t[0].id} → {t[1].param} ({t[1].source})",
                      result=result)

    def _run_target_checks(self, seeds, forms, client, result: ScanResult) -> None:
        if not self.target_checks:
            return
        self.reporter.phase("Passive checks")
        tasks = [(check, seed) for seed in seeds for check in self.target_checks]
        self._fan_out(tasks, lambda t: t[0].check_target(t[1], forms, client),
                      label=lambda t: f"{t[0].id} → {t[1]}",
                      result=result)

    def _fan_out(self, tasks, work, label, result: ScanResult) -> None:
        """Run ``work(task)`` across the thread pool, streaming findings out as
        each future completes."""
        total = len(tasks)
        done = 0
        with ThreadPoolExecutor(max_workers=self.cfg.threads) as pool:
            futures = {pool.submit(work, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    findings = future.result() or []
                except Exception as exc:  # a broken check must not sink the scan
                    findings = []
                    if self.cfg.verbose:
                        self.reporter.error(f"{label(task)} raised {exc!r}")
                for finding in findings:
                    result.findings.append(finding)
                    self.reporter.on_finding(finding)
                done += 1
                self.reporter.on_progress(done, total, label(task))
        self.reporter.progress_done()
