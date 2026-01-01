from __future__ import annotations


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{base + i:08X}  {hexpart:<{width*3}}  {asciipart}")
    return "\n".join(lines)
