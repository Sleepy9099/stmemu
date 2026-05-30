"""Replay a recorded device->MCU byte stream, paced by emulated cycles.

Constant stub responses get a driver to *detect* a device; replaying a real
capture gets it to *behave*. This feeds a recorded byte stream (a logged GPS
UBX/NMEA session, a sensor trace, ...) back to the firmware at a believable
rate so the higher layers — parsers, state machines, the EKF — see realistic
input instead of zeros.

Pacing is cycle-driven and deterministic: every ``tick_cycles`` emulated
cycles, up to ``bytes_per_tick`` bytes are released. MCU->device traffic is
captured in ``received`` for assertions. With ``loop=True`` the capture
repeats (useful for a periodic NAV stream).

    from stmemu.external.playback import PlaybackSerialDevice
    gps = PlaybackSerialDevice(data=Path("ublox_capture.ubx").read_bytes(),
                               tick_cycles=694, bytes_per_tick=1)  # ~115200 baud @ 80MHz-ish

Board config: a uart_device of type ``playback`` with ``file:`` (raw) or
``hex:`` (whitespace-separated hex) plus optional ``tick_cycles`` /
``bytes_per_tick`` / ``loop``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.external.device import ExternalDevice


@dataclass
class PlaybackSerialDevice(ExternalDevice):
    data: bytes = b""
    tick_cycles: int = 1000
    bytes_per_tick: int = 1
    loop: bool = False
    name: str = "playback"

    _pos: int = field(default=0, init=False, repr=False)
    _accum: int = field(default=0, init=False, repr=False)
    received: bytearray = field(default_factory=bytearray, init=False, repr=False)

    def __post_init__(self) -> None:
        self.data = bytes(self.data)
        self.tick_cycles = max(1, int(self.tick_cycles))
        self.bytes_per_tick = max(1, int(self.bytes_per_tick))

    # MCU -> device: just record it (a real device might ACK; playback ignores).
    def on_rx_from_mcu(self, data: bytes) -> None:
        self.received += bytes(data)

    def tick(self, cycles: int) -> None:
        self._accum += max(0, int(cycles))

    def read_tx_to_mcu(self, max_bytes: int = 4096) -> bytes:
        if not self.data:
            return b""
        if self._pos >= len(self.data) and not self.loop:
            return b""
        n_ticks = self._accum // self.tick_cycles
        if n_ticks <= 0:
            return b""
        self._accum -= n_ticks * self.tick_cycles
        budget = min(n_ticks * self.bytes_per_tick, int(max_bytes))
        out = bytearray()
        while budget > 0:
            avail = len(self.data) - self._pos
            if avail <= 0:
                if self.loop and self.data:
                    self._pos = 0
                    continue
                break
            take = min(budget, avail)
            out += self.data[self._pos:self._pos + take]
            self._pos += take
            budget -= take
        return bytes(out)

    def pending_tx_len(self) -> int:
        remaining = len(self.data) - self._pos
        return remaining if remaining > 0 or not self.loop else len(self.data)

    def reset(self) -> None:
        self._pos = 0
        self._accum = 0
        self.received = bytearray()

    def snapshot_state(self):
        return {"pos": self._pos, "accum": self._accum, "received": bytes(self.received)}

    def restore_state(self, state) -> None:
        if isinstance(state, dict):
            self._pos = int(state.get("pos", 0))
            self._accum = int(state.get("accum", 0))
            self.received = bytearray(state.get("received", b""))


__all__ = ["PlaybackSerialDevice"]
