"""Terminal presentation and report export.

The terminal output is the product here, so it gets real attention: a banner, a
live progress line, findings streamed as they're confirmed, and a severity
summary at the end. Colour degrades gracefully — it's disabled automatically
when output isn't a TTY (piped to a file, captured in CI) or when ``NO_COLOR``
is set, so logs stay clean.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime
from html import escape

from argus import __version__
from argus.config import ScanConfig
from argus.models import Confidence, Finding, ScanResult, Severity

_BANNER = r"""
    _    ____   ____ _   _ ____
   / \  |  _ \ / ___| | | / ___|
  / _ \ | |_) | |  _| | | \___ \
 / ___ \|  _ <| |_| | |_| |___) |
/_/   \_\_| \_\\____|\___/|____/
"""


class _Palette:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
    BRIGHT_RED = "\033[91m"

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def paint(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + self.RESET


# Severity -> (badge text, colour codes)
_SEV_STYLE = {
    Severity.CRITICAL: ("CRIT", (_Palette.BOLD, _Palette.BRIGHT_RED)),
    Severity.HIGH: ("HIGH", (_Palette.RED,)),
    Severity.MEDIUM: ("MED ", (_Palette.YELLOW,)),
    Severity.LOW: ("LOW ", (_Palette.BLUE,)),
    Severity.INFO: ("INFO", (_Palette.DIM,)),
}


class TerminalReporter:
    def __init__(self, config: ScanConfig):
        self.cfg = config
        self.out = sys.stdout
        colour = self._use_colour(config)
        if colour and os.name == "nt":
            # Old Windows consoles need ANSI turned on; colorama does it if it's
            # installed. Purely optional — everything works without it.
            try:
                import colorama
                colorama.just_fix_windows_console()
            except Exception:
                pass
        self.c = _Palette(colour)
        self._progress_shown = False

    @staticmethod
    def _use_colour(config: ScanConfig) -> bool:
        if config.no_color or os.environ.get("NO_COLOR"):
            return False
        return sys.stdout.isatty()

    # -- lifecycle --------------------------------------------------------
    def start(self, config: ScanConfig) -> None:
        self._write(self.c.paint(_BANNER, self.c.CYAN, self.c.BOLD))
        tagline = f"  the all-seeing web scanner  ·  v{__version__}"
        self._write(self.c.paint(tagline, self.c.DIM) + "\n\n")

        self._write(self.c.paint(
            "  Authorised testing only. Scan systems you own or have written "
            "permission to assess.\n", self.c.DIM) + "\n")

        checks_desc = ", ".join(sorted(config.enabled_checks)) if config.enabled_checks else "all"
        for label, value in (
            ("Targets", ", ".join(config.targets)),
            ("Checks", checks_desc),
            ("Crawl", f"on (depth {config.max_depth}, max {config.max_pages} pages)"
                       if config.crawl else "off"),
            ("Threads", str(config.threads)),
        ):
            self._write(f"  {self.c.paint(label + ':', self.c.BOLD):<22} {value}\n")
        self._write("\n")

    # -- engine hooks -----------------------------------------------------
    def phase(self, title: str) -> None:
        self._clear_progress()
        self._write("\n" + self.c.paint(f"── {title} ", self.c.BOLD, self.c.CYAN)
                    + self.c.paint("─" * max(0, 40 - len(title)), self.c.DIM) + "\n")

    def crawl(self, url: str) -> None:
        if self.cfg.verbose:
            self._line("*", url, self.c.DIM)

    def info(self, msg: str) -> None:
        self._line("*", msg, self.c.CYAN)

    def warn(self, msg: str) -> None:
        self._line("!", msg, self.c.YELLOW)

    def error(self, msg: str) -> None:
        self._line("-", msg, self.c.RED)

    def on_finding(self, f: Finding) -> None:
        self._clear_progress()
        badge, codes = _SEV_STYLE[f.severity]
        where = f"{f.parameter} ({f.method})" if f.parameter else f.url
        self._write(
            f"  {self.c.paint('[' + badge + ']', *codes)} "
            f"{self.c.paint(f.title, self.c.BOLD)}  {self.c.paint('· ' + where, self.c.DIM)}\n"
        )

    def on_progress(self, done: int, total: int, label: str) -> None:
        if not sys.stdout.isatty():
            return
        width = shutil.get_terminal_size((80, 20)).columns
        bar = f"[*] {done}/{total}  {label}"
        self._write("\r" + bar[: width - 1].ljust(width - 1))
        self._progress_shown = True

    def progress_done(self) -> None:
        self._clear_progress()

    # -- final report -----------------------------------------------------
    def report(self, result: ScanResult) -> None:
        self.phase("Results")
        if not result.findings:
            self._write("\n  " + self.c.paint(
                "No issues detected by the enabled checks.", self.c.GREEN) + "\n")
            self._write("  " + self.c.paint(
                "(Absence of evidence isn't evidence of absence — tune the checks "
                "and try an authenticated crawl.)", self.c.DIM) + "\n")
        else:
            self._write("\n")
            for f in result.findings:
                self._render_finding(f)
        self._render_summary(result)

    def _render_finding(self, f: Finding) -> None:
        badge, codes = _SEV_STYLE[f.severity]
        cwe = f"  {self.c.paint(f.cwe, self.c.DIM)}" if f.cwe else ""
        self._write(f"  {self.c.paint('[' + badge + ']', *codes)} "
                    f"{self.c.paint(f.title, self.c.BOLD)}{cwe}\n")

        rows = [("URL", f.url)]
        if f.parameter:
            rows.append(("Parameter", f"{f.parameter}  ({f.method})"))
        if f.payload:
            rows.append(("Payload", f.payload))
        rows.append(("Evidence", f.evidence))
        rows.append(("Confidence", f.confidence.label))
        rows.append(("Fix", f.remediation))
        for label, value in rows:
            if not value:
                continue
            self._write(f"      {self.c.paint(label + ':', self.c.DIM):<18} {value}\n")
        self._write("\n")

    def _render_summary(self, result: ScanResult) -> None:
        counts = result.counts_by_severity()
        self._write(self.c.paint("  Summary\n", self.c.BOLD))
        for sev in sorted(Severity, reverse=True):
            n = counts[sev]
            if n == 0:
                continue
            badge, codes = _SEV_STYLE[sev]
            self._write(f"    {self.c.paint(badge.strip().ljust(8), *codes)} {n}\n")

        total = len(result.findings)
        headline = f"{total} finding{'s' if total != 1 else ''}"
        colour = (self.c.GREEN,) if total == 0 else (self.c.BOLD, self.c.YELLOW)
        self._write("\n  " + self.c.paint(headline, *colour) + "\n")
        self._write("  " + self.c.paint(
            f"{result.urls_crawled} URL(s) · {result.injection_points} injection point(s) · "
            f"{result.requests_sent} request(s) · {result.duration:.1f}s",
            self.c.DIM) + "\n")

    # -- low-level --------------------------------------------------------
    def _line(self, tag: str, msg: str, *codes: str) -> None:
        self._clear_progress()
        self._write(f"  {self.c.paint('[' + tag + ']', *codes)} {msg}\n")

    def _clear_progress(self) -> None:
        if self._progress_shown and sys.stdout.isatty():
            width = shutil.get_terminal_size((80, 20)).columns
            self._write("\r" + " " * (width - 1) + "\r")
            self._progress_shown = False

    def _write(self, text: str) -> None:
        self.out.write(text)
        self.out.flush()


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------
def _finding_dict(f: Finding) -> dict:
    return {
        "check": f.check, "title": f.title,
        "severity": f.severity.label, "confidence": f.confidence.label,
        "url": f.url, "parameter": f.parameter, "method": f.method,
        "payload": f.payload, "evidence": f.evidence,
        "description": f.description, "remediation": f.remediation,
        "cwe": f.cwe, "references": list(f.references),
    }


def _report_metadata(result: ScanResult, config: ScanConfig) -> dict:
    return {
        "tool": "argus", "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "targets": config.targets,
        "stats": {
            "findings": len(result.findings),
            "urls_crawled": result.urls_crawled,
            "injection_points": result.injection_points,
            "requests_sent": result.requests_sent,
            "duration_seconds": round(result.duration, 2),
            "by_severity": {s.label: n for s, n in result.counts_by_severity().items()},
        },
    }


def to_json(result: ScanResult, config: ScanConfig, path: str) -> None:
    payload = _report_metadata(result, config)
    payload["findings"] = [_finding_dict(f) for f in result.findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


_HTML_SEV_COLOUR = {
    "Critical": "#b3005c", "High": "#d13438", "Medium": "#f2a900",
    "Low": "#0a84ff", "Info": "#8a8a8a",
}


def to_html(result: ScanResult, config: ScanConfig, path: str) -> None:
    meta = _report_metadata(result, config)
    rows = []
    for f in result.findings:
        colour = _HTML_SEV_COLOUR.get(f.severity.label, "#666")
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{colour}">{escape(f.severity.label)}</span></td>
          <td><strong>{escape(f.title)}</strong><br><span class="cwe">{escape(f.cwe or '')}</span></td>
          <td class="mono">{escape(f.url)}<br>{escape((f.parameter or '') + ' ' + f.method)}</td>
          <td class="mono">{escape(f.payload or '')}</td>
          <td>{escape(f.evidence)}<br><span class="fix">Fix: {escape(f.remediation)}</span></td>
        </tr>""")

    stats = meta["stats"]
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Argus scan report</title>
<style>
  body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; color: #1c1c1e; background: #f5f5f7; }}
  header {{ background: #0b0b0d; color: #f5f5f7; padding: 28px 40px; }}
  header h1 {{ margin: 0; font-size: 22px; letter-spacing: .5px; }}
  header p {{ margin: 6px 0 0; color: #9a9a9e; font-size: 13px; }}
  .wrap {{ padding: 28px 40px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{ background: #fff; border-radius: 10px; padding: 14px 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .stat b {{ display: block; font-size: 24px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ text-align: left; padding: 12px 14px; vertical-align: top; border-bottom: 1px solid #eee; font-size: 13px; }}
  th {{ background: #fafafa; text-transform: uppercase; letter-spacing: .5px; font-size: 11px; color: #666; }}
  .sev {{ color: #fff; padding: 2px 9px; border-radius: 20px; font-size: 11px; font-weight: 700; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; word-break: break-all; }}
  .cwe {{ color: #999; font-size: 11px; }}
  .fix {{ color: #0a7d33; font-size: 12px; }}
  footer {{ padding: 20px 40px; color: #999; font-size: 12px; }}
</style></head><body>
<header>
  <h1>Argus &mdash; Web Vulnerability Scan Report</h1>
  <p>{escape(', '.join(config.targets))} · generated {escape(meta['generated_at'])} · v{escape(meta['version'])}</p>
</header>
<div class="wrap">
  <div class="stats">
    <div class="stat"><b>{stats['findings']}</b>findings</div>
    <div class="stat"><b>{stats['urls_crawled']}</b>URLs</div>
    <div class="stat"><b>{stats['injection_points']}</b>injection points</div>
    <div class="stat"><b>{stats['requests_sent']}</b>requests</div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Issue</th><th>Location</th><th>Payload</th><th>Evidence &amp; Fix</th></tr></thead>
    <tbody>{''.join(rows) or '<tr><td colspan="5">No issues detected.</td></tr>'}</tbody>
  </table>
</div>
<footer>Generated by Argus. For authorised security testing only.</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(document)
