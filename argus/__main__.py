"""Enable ``python -m argus`` as an entry point equivalent to the console script."""
from __future__ import annotations

from argus.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
