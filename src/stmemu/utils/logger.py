from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO", quiet: bool = False) -> None:
    root = logging.getLogger()
    root.handlers.clear()

    lvl = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(lvl)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(lvl)
    fmt = "[%(levelname)s] %(name)s: %(message)s" if not quiet else "%(message)s"
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
