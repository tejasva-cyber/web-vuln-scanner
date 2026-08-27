"""Command-line interface.

Turns argv into a :class:`ScanConfig`, runs the engine, and returns a
CI-friendly exit code (non-zero when findings exist), so the scanner drops
straight into a pipeline gate if you want it there.
"""
from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from argus import __version__, checks
from argus.config import DEFAULT_USER_AGENT, ScanConfig
from argus.reporter import TerminalReporter, to_html, to_json
from argus.scanner import ScanEngine

_EPILOG = """\
examples:
  argus http://localhost:8000/                 scan a single target
  argus -u http://a.tld -u http://b.tld        scan several targets
  argus http://site.tld/ --crawl --depth 3     crawl same-origin, then scan
  argus http://site.tld/?id=1 --checks sqli,xss   only run selected checks
  argus http://site.tld/ --json report.json --html report.html

Authorised testing only. You are responsible for having permission to scan
every target you pass. See the README for the full usage policy.
"""


def _normalise_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    # Bare host -> assume http:// so users can type "localhost:8000".
    if not urlparse(raw).scheme:
        raw = "http://" + raw
    return raw


def _load_targets(args) -> list[str]:
    targets: list[str] = list(args.targets) + list(args.url)
    if args.url_file:
        try:
            with open(args.url_file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            raise SystemExit(f"argus: cannot read --url-file: {exc}")
    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for t in map(_normalise_target, targets):
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _parse_pairs(values: list[str], sep: str, flag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        if sep not in item:
            raise SystemExit(f"argus: {flag} expects 'name{sep}value', got {item!r}")
        key, value = item.split(sep, 1)
        out[key.strip()] = value.strip()
    return out


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="Argus — a lightweight web application vulnerability scanner.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="target URL(s) to scan")
    p.add_argument("-u", "--url", action="append", default=[],
                   help="add a target URL (repeatable)")
    p.add_argument("--url-file", help="file of target URLs, one per line")

    crawl = p.add_argument_group("crawling")
    crawl.add_argument("--crawl", action="store_true",
                       help="follow same-origin links to discover more inputs")
    crawl.add_argument("--depth", type=int, default=2, dest="max_depth",
                       help="max crawl depth (default: 2)")
    crawl.add_argument("--max-pages", type=int, default=60,
                       help="max pages to fetch while crawling (default: 60)")

    net = p.add_argument_group("network")
    net.add_argument("-t", "--threads", type=int, default=10,
                     help="concurrent workers (default: 10)")
    net.add_argument("--delay", type=float, default=0.0,
                     help="seconds between requests, globally (default: 0)")
    net.add_argument("--timeout", type=float, default=10.0,
                     help="per-request timeout in seconds (default: 10)")
    net.add_argument("--retries", type=int, default=2,
                     help="retries on transient errors (default: 2)")
    net.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="override User-Agent")
    net.add_argument("-H", "--header", action="append", default=[], metavar="NAME:VALUE",
                     help="add a request header (repeatable)")
    net.add_argument("-b", "--cookie", action="append", default=[], metavar="NAME=VALUE",
                     help="add a cookie (repeatable)")
    net.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    net.add_argument("-k", "--insecure", action="store_true",
                     help="skip TLS certificate verification")

    sel = p.add_argument_group("checks & output")
    sel.add_argument("-c", "--checks",
                     help="comma-separated check ids to run (default: all)")
    sel.add_argument("--list-checks", action="store_true",
                     help="list available checks and exit")
    sel.add_argument("--json", metavar="PATH", help="write findings to a JSON file")
    sel.add_argument("--html", metavar="PATH", help="write an HTML report")
    sel.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    sel.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--version", action="version", version=f"argus {__version__}")
    return p


def _resolve_checks(spec: str | None) -> set[str] | None:
    if not spec:
        return None
    requested = {c.strip() for c in spec.split(",") if c.strip()}
    unknown = requested - checks.known_ids()
    if unknown:
        raise SystemExit(
            f"argus: unknown check(s): {', '.join(sorted(unknown))}\n"
            f"       available: {', '.join(sorted(checks.known_ids()))}"
        )
    return requested


def main(argv: list[str] | None = None) -> int:
    # Make Unicode in the output safe on legacy Windows consoles.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    args = _build_parser().parse_args(argv)

    if args.list_checks:
        print("Available checks:\n")
        for cid, desc in checks.available().items():
            print(f"  {cid:<10} {desc}")
        return 0

    targets = _load_targets(args)
    if not targets:
        print("argus: no targets given. Try 'argus --help'.", file=sys.stderr)
        return 2

    config = ScanConfig(
        targets=targets,
        crawl=args.crawl,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        threads=max(1, args.threads),
        delay=max(0.0, args.delay),
        timeout=args.timeout,
        retries=args.retries,
        user_agent=args.user_agent,
        headers=_parse_pairs(args.header, ":", "--header"),
        cookies=_parse_pairs(args.cookie, "=", "--cookie"),
        proxy=args.proxy,
        verify_tls=not args.insecure,
        enabled_checks=_resolve_checks(args.checks),
        verbose=args.verbose,
        no_color=args.no_color,
        output_json=args.json,
        output_html=args.html,
    )

    reporter = TerminalReporter(config)
    reporter.start(config)

    try:
        result = ScanEngine(config, reporter).run()
    except KeyboardInterrupt:
        reporter.warn("Interrupted — partial results discarded.")
        return 130

    reporter.report(result)

    if config.output_json:
        to_json(result, config, config.output_json)
        reporter.info(f"JSON report written to {config.output_json}")
    if config.output_html:
        to_html(result, config, config.output_html)
        reporter.info(f"HTML report written to {config.output_html}")

    # Non-zero exit when anything was found — handy as a CI gate.
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
