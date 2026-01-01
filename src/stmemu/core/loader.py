from __future__ import annotations

from pathlib import Path


def load_raw_bin(path: Path) -> bytes:
    return path.read_bytes()
