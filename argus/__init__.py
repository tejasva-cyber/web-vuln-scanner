"""Argus — a lightweight web application vulnerability scanner.

Named after Argus Panoptes, the hundred-eyed giant of Greek myth who never
slept. The idea is the same: keep an eye on every input a web app exposes and
notice when one of them misbehaves.

Argus is an educational / authorised-testing tool. Point it only at systems you
own or have explicit written permission to assess. See the README for the full
usage policy.
"""
from __future__ import annotations

__title__ = "argus"
__version__ = "0.4.1"
__author__ = "Tejasva"
__license__ = "MIT"
__url__ = "https://github.com/tejasva/argus"

# Kept intentionally import-light: pulling the engine in here would create an
# import cycle (cli -> scanner -> checks -> ... -> argus). Import from the
# submodules directly instead.
__all__ = ["__version__", "__title__", "__author__", "__license__"]
