"""Payloads and detection signatures.

This module is deliberately data-heavy and logic-light: the *what to send* and
*what to look for* lives here, the *how to decide* lives in ``argus/checks``.
Splitting them means tuning a signature never risks touching detection logic,
and the signatures can be unit-tested in isolation (see ``tests/``).
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------
# Database error strings that leak when a stray quote breaks a query. Grouped by
# engine mostly so the evidence we report can name the backend.
_SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysqli?_",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"MySqlException",
        r"valid MySQL result",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
    ],
    "Microsoft SQL Server": [
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error",
        r"OLE DB.*?SQL Server",
        r"\bSQL Server[^&<]+Driver",
        r"System\.Data\.SqlClient\.SqlException",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}",
        r"Oracle error",
        r"quoted string not properly terminated",
        r"Oracle.*?Driver",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\bsqlite_",
        r"sqlite3\.OperationalError",
        r"\[SQLITE_ERROR\]",
    ],
}

# Pre-compiled, tagged with their engine, case-insensitive.
SQL_ERROR_SIGNATURES: list[tuple[str, re.Pattern]] = [
    (engine, re.compile(pat, re.IGNORECASE))
    for engine, patterns in _SQL_ERROR_PATTERNS.items()
    for pat in patterns
]

# Payloads that tend to trip an unescaped query into an error.
SQLI_ERROR_PAYLOADS: tuple[str, ...] = ("'", '"', "')", "';", "\\")

# Boolean pairs for differential testing: a logically-true and logically-false
# clause. If "true" looks like the original page and "false" looks different,
# the parameter is talking to the database.
SQLI_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1-- -", " AND 1=2-- -"),
)


# ---------------------------------------------------------------------------
# Cross-site scripting (reflected)
# ---------------------------------------------------------------------------
# Each payload carries a {token} we can grep for. We care less about the exact
# vector and more about whether the metacharacters (< > " ') survive un-encoded,
# which is the precondition for reflected XSS.
XSS_PROBES: tuple[str, ...] = (
    "<{token}>",
    '"><{token}>',
    "'><{token}>",
    "<img src=x onerror={token}>",
)

# The characters that must be encoded for output to be safe.
XSS_DANGEROUS_CHARS = ("<", ">", '"', "'")


# ---------------------------------------------------------------------------
# Path traversal / local file inclusion
# ---------------------------------------------------------------------------
PATH_TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
)

PATH_TRAVERSAL_SIGNATURES: tuple[re.Pattern, ...] = (
    re.compile(r"root:.*?:0:0:", re.IGNORECASE),         # /etc/passwd
    re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE),  # win.ini
    re.compile(r"for 16-bit app support", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# OS command injection (time-based)
# ---------------------------------------------------------------------------
# Time-based is OS-tolerant and doesn't rely on output reflection: we inject a
# command that sleeps, and infer injection from the response delay.
def command_injection_payloads(delay: int) -> tuple[str, ...]:
    return (
        f"; sleep {delay}",
        f"| sleep {delay}",
        f"& sleep {delay}",
        f"`sleep {delay}`",
        f"$(sleep {delay})",
        f"; ping -c {delay} 127.0.0.1",              # *nix, ~1s per echo
        f"& ping -n {delay + 1} 127.0.0.1 &",        # Windows
    )


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------
# A host we obviously don't control. If a redirect lands here, the parameter is
# attacker-controllable.
OPEN_REDIRECT_CANARY = "argus-canary.example"
OPEN_REDIRECT_PAYLOADS: tuple[str, ...] = (
    f"https://{OPEN_REDIRECT_CANARY}/",
    f"//{OPEN_REDIRECT_CANARY}/",
    f"https:/{OPEN_REDIRECT_CANARY}/",
    f"/\\{OPEN_REDIRECT_CANARY}/",
)

# Parameter names that most often carry a redirect target — used to prioritise,
# not to restrict.
REDIRECT_PARAM_HINTS = (
    "next", "url", "redirect", "redirect_uri", "return", "returnurl",
    "return_to", "dest", "destination", "continue", "goto", "out", "target",
)


# ---------------------------------------------------------------------------
# Sensitive files left in the web root
# ---------------------------------------------------------------------------
# (path, optional content signature, why-it-matters). The signature keeps a
# custom 404 page from being mistaken for a real hit.
SENSITIVE_PATHS: tuple[tuple[str, str | None, str], ...] = (
    ("/.git/HEAD", r"ref:\s", "Exposed Git repository — full source history may be downloadable"),
    ("/.git/config", r"\[core\]", "Exposed Git config — repository metadata and remotes"),
    ("/.env", r"(?m)^[A-Z0-9_]+=", "Environment file — often contains secrets and DB credentials"),
    ("/.env.local", r"(?m)^[A-Z0-9_]+=", "Local environment file — often contains secrets"),
    ("/config.php.bak", None, "Backup of PHP config — may contain credentials in cleartext"),
    ("/wp-config.php.bak", None, "Backup of WordPress config — database credentials"),
    ("/.svn/entries", None, "Exposed Subversion metadata"),
    ("/.DS_Store", r"Bud1", "macOS directory index — leaks file names"),
    ("/backup.zip", None, "Site backup archive left in web root"),
    ("/backup.sql", None, "Database dump left in web root"),
    ("/phpinfo.php", r"phpinfo\(\)", "phpinfo() page — leaks server configuration"),
    ("/server-status", r"Apache Server Status", "Apache status page exposed"),
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
# (header, severity-if-missing, short rationale). Presence/quality is judged in
# the check; this is the catalogue.
SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("Content-Security-Policy", "medium",
     "No CSP: nothing constrains where scripts/styles may load from"),
    ("Strict-Transport-Security", "medium",
     "No HSTS: browser may fall back to plaintext HTTP (only checked over HTTPS)"),
    ("X-Frame-Options", "low",
     "No framing policy: page may be embedded for clickjacking (CSP frame-ancestors also counts)"),
    ("X-Content-Type-Options", "low",
     "No nosniff: browser may MIME-sniff responses"),
    ("Referrer-Policy", "info",
     "No referrer policy: full URLs may leak to third parties"),
)
