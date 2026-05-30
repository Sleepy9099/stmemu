"""Declarative register-file primitives for device models.

Hand-writing each device's register read/write/quirk logic is the bulk of a new
device model — we did it again for the IMU FIFOs. This turns the common cases
into *data*: declare a register's offset, name, and semantics, and the
``RegisterFile`` handles reads/writes. New SPI/I2C devices become mostly a table
of :class:`Register` rows plus a thin transaction shim.

Per-register semantics
----------------------
  ``rw``    plain read/write (default)
  ``ro``    read-only; writes are ignored
  ``w1c``   write-1-to-clear; writing a 1 bit clears it, 0 bits unchanged
  ``fifo``  streaming FIFO; reads pop successive bytes WITHOUT auto-incrementing
            the register address (as for IMU ``FIFO_DATA``); device feeds bytes
            via :meth:`RegisterFile.feed_fifo`

Bosch-style read-dummy (the first byte of a read burst is a discarded dummy) is
a transaction-level quirk rather than a register value, so it is exposed as the
``read_dummy`` flag for the device's SPI handler to honor.

Everything is keyed on register offsets, so it works for any device on a raw
bin. :meth:`RegisterFile.describe` names a register for the tracer / stall
analyzer.

Example
-------
    from stmemu.external.register_file import Register, RegisterFile
    rf = RegisterFile([
        Register(0x75, "WHO_AM_I", "ro", reset=0x47),
        Register(0x1F, "INT_STATUS", "w1c"),
        Register(0x3F, "FIFO_DATA", "fifo"),
        Register(0x4E, "PWR_MGMT0"),            # rw
    ], read_dummy=False)
    rf.read(0x75)                # -> 0x47 (read-only)
    rf.feed_fifo(0x3F, bytes(6)) # device pushes a sample frame
    rf.read(0x3F)                # -> next FIFO byte, no address increment
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

VALID_KINDS = ("rw", "ro", "w1c", "fifo")


@dataclass
class Register:
    offset: int
    name: str = ""
    kind: str = "rw"          # rw | ro | w1c | fifo
    reset: int = 0
    mask: int = 0xFF          # 0xFF for 8-bit regs, 0xFFFF for 16-bit, ...
    _value: int = field(default=0, init=False, repr=False)
    _fifo: deque = field(default_factory=deque, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.kind not in VALID_KINDS:
            raise ValueError(f"register {self.offset:#x}: bad kind {self.kind!r}")
        self.reset_value()

    def reset_value(self) -> None:
        self._value = self.reset & self.mask
        self._fifo.clear()


class RegisterFile:
    """A bank of :class:`Register` rows with read/write dispatch by semantics."""

    def __init__(self, registers, *, read_dummy: bool = False, default: int = 0) -> None:
        self._regs: dict[int, Register] = {}
        for r in registers:
            self._regs[int(r.offset)] = r
        self.read_dummy = bool(read_dummy)
        self._default = int(default) & 0xFF

    # ── queries ────────────────────────────────────────────────────────
    def has(self, offset: int) -> bool:
        return int(offset) in self._regs

    def describe(self, offset: int):
        r = self._regs.get(int(offset))
        return r.name if (r and r.name) else None

    def fifo_len(self, offset: int) -> int:
        r = self._regs.get(int(offset))
        return len(r._fifo) if (r and r.kind == "fifo") else 0

    # ── access dispatch ────────────────────────────────────────────────
    def read(self, offset: int) -> int:
        r = self._regs.get(int(offset))
        if r is None:
            return self._default
        if r.kind == "fifo":
            return r._fifo.popleft() if r._fifo else self._default
        return r._value & r.mask

    def write(self, offset: int, value: int) -> None:
        r = self._regs.get(int(offset))
        if r is None:
            return
        v = int(value) & r.mask
        if r.kind in ("ro", "fifo"):
            return                       # read-only / read-only stream
        if r.kind == "w1c":
            r._value &= (~v) & r.mask     # writing 1 clears that bit
            return
        r._value = v                      # rw

    # ── device-side backdoors (bypass ro/w1c) ─────────────────────────
    def set(self, offset: int, value: int) -> None:
        """Set a register value from the device side, bypassing ro/w1c."""
        r = self._regs.get(int(offset))
        if r is not None:
            r._value = int(value) & r.mask

    def get(self, offset: int) -> int:
        r = self._regs.get(int(offset))
        return (r._value & r.mask) if r is not None else self._default

    def feed_fifo(self, offset: int, data) -> None:
        """Push byte(s) into a ``fifo`` register's stream (device side)."""
        r = self._regs.get(int(offset))
        if r is None or r.kind != "fifo":
            return
        if isinstance(data, int):
            r._fifo.append(data & 0xFF)
        else:
            r._fifo.extend(int(b) & 0xFF for b in data)

    def clear_fifo(self, offset: int) -> None:
        r = self._regs.get(int(offset))
        if r is not None and r.kind == "fifo":
            r._fifo.clear()

    # ── lifecycle / snapshot ──────────────────────────────────────────
    def reset(self) -> None:
        for r in self._regs.values():
            r.reset_value()

    def snapshot_state(self) -> dict:
        return {off: (r._value, list(r._fifo)) for off, r in self._regs.items()}

    def restore_state(self, state) -> None:
        if not isinstance(state, dict):
            return
        for off, r in self._regs.items():
            if off in state:
                v, fifo = state[off]
                r._value = int(v) & r.mask
                r._fifo.clear()
                r._fifo.extend(int(b) & 0xFF for b in fifo)


__all__ = ["Register", "RegisterFile", "VALID_KINDS"]
