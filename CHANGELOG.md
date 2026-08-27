# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic
versioning.

## [0.4.1] — 2026-08-24
### Fixed
- Distinct issues on the same URL (e.g. several missing security headers) were
  being collapsed into one during de-duplication. The finding fingerprint now
  includes the title, so they're reported separately. Added a regression test.

## [0.4.0] — 2026-08-18
### Added
- JSON and HTML report export (`--json`, `--html`).
- Live, colourised terminal output: banner, streaming findings, severity summary.
- `--list-checks` and per-check selection with `--checks`.
- Deliberately-vulnerable demo app under `examples/` to test against safely.

### Changed
- Colour is now auto-disabled when output isn't a TTY or `NO_COLOR` is set.

## [0.3.0] — 2026-07-30
### Added
- Same-origin crawler (`--crawl`) that discovers links and forms, bounded by
  depth and page count.
- Concurrency via a thread pool with a global, thread-safe rate limiter.
- Passive checks: security headers, cookie flags, sensitive-file exposure.

## [0.2.0] — 2026-07-15
### Changed
- Replaced the original "an input exists, therefore it's vulnerable" heuristic
  with real detection: error- and boolean-based SQLi, reflected-XSS probes,
  path-traversal signatures, time-based command injection, open redirect.

## [0.1.0] — 2026-07-02
### Added
- First cut: six parameter checks over a list of URLs, plain-text output.
