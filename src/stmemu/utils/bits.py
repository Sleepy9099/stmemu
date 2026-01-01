from __future__ import annotations


def mask_for_size(size: int) -> int:
    if size == 1:
        return 0xFF
    if size == 2:
        return 0xFFFF
    if size == 4:
        return 0xFFFFFFFF
    # fallback (Unicorn can request odd sizes)
    return (1 << (size * 8)) - 1
