"""Input mutation engine for coverage-guided fuzzing."""
from __future__ import annotations

import os
import random
import struct
from typing import Sequence


# Interesting boundary values for byte-level mutations
_INTERESTING_8 = [0, 1, 0x7F, 0x80, 0xFF]
_INTERESTING_16 = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]
_INTERESTING_32 = [
    0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
    0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]


class Mutator:
    """Generate and mutate byte sequences for fuzzing."""

    def __init__(self, seed: int | None = None, dictionary: list[bytes] | None = None) -> None:
        self._rng = random.Random(seed)
        self._dictionary: list[bytes] = list(dictionary or [])

    def set_seed(self, seed: int) -> None:
        self._rng.seed(seed)

    def add_dict_entry(self, entry: bytes) -> None:
        if entry and entry not in self._dictionary:
            self._dictionary.append(entry)

    # ── Generation ─────────────────────────────────────────────────

    def generate(self, min_len: int = 1, max_len: int = 256) -> bytearray:
        """Generate a fully random input."""
        length = self._rng.randint(max(1, min_len), max(1, max_len))
        return bytearray(self._rng.getrandbits(8) for _ in range(length))

    # ── Mutation strategies ────────────────────────────────────────

    def mutate(
        self, data: bytes, max_mutations: int = 4, max_len: int = 0,
    ) -> bytearray:
        """Apply 1..max_mutations random mutation strategies to data.

        If *max_len* > 0, the result is truncated after each mutation so that
        insert/duplicate strategies cannot grow inputs beyond the intended
        packet size.
        """
        if not data:
            return self.generate(max_len=max_len if max_len > 0 else 256)
        buf = bytearray(data)
        n = self._rng.randint(1, max(1, max_mutations))
        strategies = [
            self._flip_bit,
            self._flip_byte,
            self._arith_byte,
            self._interesting_byte,
            self._interesting_16,
            self._interesting_32,
            self._insert_bytes,
            self._delete_bytes,
            self._overwrite_chunk,
            self._duplicate_chunk,
            self._shuffle_chunk,
        ]
        if self._dictionary:
            strategies.append(self._insert_dict)
            strategies.append(self._overwrite_dict)
        for _ in range(n):
            strategy = self._rng.choice(strategies)
            buf = strategy(buf)
            if max_len > 0 and len(buf) > max_len:
                buf = buf[:max_len]
        return buf

    def splice(self, a: bytes, b: bytes, max_len: int = 0) -> bytearray:
        """Splice two inputs together at random crossover points."""
        if not a:
            result = bytearray(b)
        elif not b:
            result = bytearray(a)
        else:
            cut_a = self._rng.randint(0, len(a))
            cut_b = self._rng.randint(0, len(b))
            result = bytearray(a[:cut_a]) + bytearray(b[cut_b:])
        if max_len > 0 and len(result) > max_len:
            result = result[:max_len]
        return result

    # ── Individual strategies ──────────────────────────────────────

    def _flip_bit(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        idx = self._rng.randint(0, len(buf) - 1)
        bit = 1 << self._rng.randint(0, 7)
        buf[idx] ^= bit
        return buf

    def _flip_byte(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        idx = self._rng.randint(0, len(buf) - 1)
        buf[idx] ^= 0xFF
        return buf

    def _arith_byte(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        idx = self._rng.randint(0, len(buf) - 1)
        delta = self._rng.randint(-35, 35)
        buf[idx] = (buf[idx] + delta) & 0xFF
        return buf

    def _interesting_byte(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        idx = self._rng.randint(0, len(buf) - 1)
        buf[idx] = self._rng.choice(_INTERESTING_8) & 0xFF
        return buf

    def _interesting_16(self, buf: bytearray) -> bytearray:
        if len(buf) < 2:
            return buf
        idx = self._rng.randint(0, len(buf) - 2)
        val = self._rng.choice(_INTERESTING_16)
        endian = self._rng.choice(["<", ">"])
        struct.pack_into(f"{endian}H", buf, idx, val & 0xFFFF)
        return buf

    def _interesting_32(self, buf: bytearray) -> bytearray:
        if len(buf) < 4:
            return buf
        idx = self._rng.randint(0, len(buf) - 4)
        val = self._rng.choice(_INTERESTING_32)
        endian = self._rng.choice(["<", ">"])
        struct.pack_into(f"{endian}I", buf, idx, val & 0xFFFFFFFF)
        return buf

    def _insert_bytes(self, buf: bytearray) -> bytearray:
        count = self._rng.randint(1, 16)
        pos = self._rng.randint(0, len(buf))
        chunk = bytearray(self._rng.getrandbits(8) for _ in range(count))
        return buf[:pos] + chunk + buf[pos:]

    def _delete_bytes(self, buf: bytearray) -> bytearray:
        if len(buf) <= 1:
            return buf
        count = self._rng.randint(1, min(16, len(buf) - 1))
        pos = self._rng.randint(0, len(buf) - count)
        return buf[:pos] + buf[pos + count:]

    def _overwrite_chunk(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        count = self._rng.randint(1, min(16, len(buf)))
        pos = self._rng.randint(0, len(buf) - count)
        for i in range(count):
            buf[pos + i] = self._rng.getrandbits(8)
        return buf

    def _duplicate_chunk(self, buf: bytearray) -> bytearray:
        if not buf:
            return buf
        count = self._rng.randint(1, min(32, len(buf)))
        src = self._rng.randint(0, len(buf) - count)
        dst = self._rng.randint(0, len(buf))
        chunk = buf[src:src + count]
        return buf[:dst] + chunk + buf[dst:]

    def _shuffle_chunk(self, buf: bytearray) -> bytearray:
        if len(buf) < 2:
            return buf
        count = self._rng.randint(2, min(16, len(buf)))
        pos = self._rng.randint(0, len(buf) - count)
        chunk = list(buf[pos:pos + count])
        self._rng.shuffle(chunk)
        buf[pos:pos + count] = chunk
        return buf

    def _insert_dict(self, buf: bytearray) -> bytearray:
        if not self._dictionary:
            return buf
        entry = self._rng.choice(self._dictionary)
        pos = self._rng.randint(0, len(buf))
        return buf[:pos] + bytearray(entry) + buf[pos:]

    def _overwrite_dict(self, buf: bytearray) -> bytearray:
        if not self._dictionary or not buf:
            return buf
        entry = self._rng.choice(self._dictionary)
        if len(entry) > len(buf):
            return buf[:0] + bytearray(entry) + buf[len(entry):]
        pos = self._rng.randint(0, len(buf) - len(entry))
        buf[pos:pos + len(entry)] = entry
        return buf
