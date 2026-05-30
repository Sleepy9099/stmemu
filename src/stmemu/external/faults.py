"""Deterministic fault injection for external devices.

The point of the emulator is to *test* drivers against their devices, which
means exercising the unhappy paths a real bus throws at firmware: a sensor
that returns a stuck bit, a corrupted FIFO word, a dropped byte, an I2C NAK.
This wraps a real device model in a decorator that perturbs its responses
according to declarative rules — so a scenario can ask "every 10th read of
WHOAMI, flip a bit" without touching the device model.

Everything is **deterministic**: faults fire on an access *index*, never on a
random draw, so a run is reproducible and a regression test can assert the
exact firmware reaction.

    from stmemu.external.faults import FaultRule, FaultySpiDevice
    dev = FaultySpiDevice(Icm42688Device(name="icm"),
                          [FaultRule(kind="stuck", reg=0x75, value=0x00)])
    # now the ICM reports a stuck-at-zero WHOAMI -> driver should fail to probe

Rule fields
-----------
kind   : what to do  -- "stuck" | "corrupt" | "drop" | "nak"
when   : when to fire -- "every" (every `every`-th matching access from `after`),
                         "after" (every access at/after index `after`),
                         "once"  (only at index `after`)
after  : first matching access index this rule considers (0-based)
every  : period for when="every"
limit  : max number of times this rule may fire (0 = unlimited)
reg    : SPI only — restrict to transactions whose register byte matches
mask   : "corrupt" XOR mask applied to the response byte
value  : "stuck" forced response byte

Indexing is per **transaction** for SPI (one CS-asserted exchange burst) and
per **chunk** for UART (one device->MCU emission), which is the granularity a
test usually wants to talk about ("the 3rd read", "every UART frame").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from stmemu.external.device import ExternalDevice


@dataclass
class FaultRule:
    kind: str = "corrupt"          # stuck | corrupt | drop | nak
    when: str = "every"            # every | after | once
    after: int = 0
    every: int = 1
    limit: int = 0
    reg: Optional[int] = None      # SPI register filter (low 7 bits of cmd byte)
    mask: int = 0xFF
    value: int = 0xFF
    _fired: int = field(default=0, init=False, repr=False)

    # ── trigger logic ───────────────────────────────────────────────────
    def reg_matches(self, reg: Optional[int]) -> bool:
        return self.reg is None or (reg is not None and (reg & 0x7F) == (self.reg & 0x7F))

    def triggers(self, index: int) -> bool:
        if self.limit and self._fired >= self.limit:
            return False
        if index < self.after:
            return False
        if self.when == "once":
            return index == self.after
        if self.when == "after":
            return True
        # "every": every `every`-th access counting from `after`
        return (index - self.after) % max(1, self.every) == 0

    def fire(self) -> None:
        self._fired += 1

    def transform_byte(self, byte: int) -> int:
        if self.kind == "stuck":
            return self.value & 0xFF
        if self.kind == "corrupt":
            return (byte ^ self.mask) & 0xFF
        if self.kind in ("drop", "nak"):
            return 0xFF
        return byte & 0xFF

    def reset(self) -> None:
        self._fired = 0


def _byte_rules(rules: List[FaultRule]) -> List[FaultRule]:
    return [r for r in rules if r.kind in ("stuck", "corrupt", "drop")]


# ── SPI ────────────────────────────────────────────────────────────────

@dataclass
class FaultySpiDevice(ExternalDevice):
    """Wrap an SPI slave and perturb its MISO responses per the rules.

    The first byte of each CS transaction is treated as the command/address
    (Bosch/Invensense convention: bit7 = read, low 7 = register); faults apply
    to the *data* bytes of a transaction whose register matches a rule.
    """

    inner: object = None
    rules: List[FaultRule] = field(default_factory=list)
    name: str = ""

    _txn: int = field(default=-1, init=False, repr=False)   # transaction index
    _reg: Optional[int] = field(default=None, init=False, repr=False)
    _byte_in_txn: int = field(default=0, init=False, repr=False)
    faults_applied: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"faulty:{getattr(self.inner, 'name', 'spi')}"

    # CS state mirrors the inner device.
    @property
    def cs_active(self) -> bool:
        return bool(getattr(self.inner, "cs_active", False))

    def cs_select(self) -> None:
        self._txn += 1
        self._reg = None
        self._byte_in_txn = 0
        if hasattr(self.inner, "cs_select"):
            self.inner.cs_select()

    def cs_release(self) -> None:
        if hasattr(self.inner, "cs_release"):
            self.inner.cs_release()

    def exchange(self, mosi: int) -> int:
        miso = int(self.inner.exchange(mosi)) & 0xFF
        if self._byte_in_txn == 0:
            # first byte of the burst is the command: capture the register
            self._reg = mosi & 0x7F
            self._byte_in_txn += 1
            return miso  # never fault the address byte itself
        self._byte_in_txn += 1
        for rule in _byte_rules(self.rules):
            if rule.reg_matches(self._reg) and rule.triggers(self._txn):
                miso = rule.transform_byte(miso)
                rule.fire()
                self.faults_applied += 1
        return miso

    # delegate everything else
    def tick(self, cycles: int) -> None:
        if hasattr(self.inner, "tick"):
            self.inner.tick(cycles)

    def reset(self) -> None:
        self._txn = -1
        self._reg = None
        self._byte_in_txn = 0
        for r in self.rules:
            r.reset()
        if hasattr(self.inner, "reset"):
            self.inner.reset()

    def snapshot_state(self):
        return self.inner.snapshot_state() if hasattr(self.inner, "snapshot_state") else None

    def restore_state(self, state) -> None:
        if hasattr(self.inner, "restore_state"):
            self.inner.restore_state(state)


# ── UART / serial ────────────────────────────────────────────────────────

@dataclass
class FaultySerialDevice(ExternalDevice):
    """Wrap a serial device and perturb the device->MCU byte stream.

    Faults apply per emission chunk (one ``read_tx_to_mcu`` that returns data):
    "drop" swallows the whole chunk, "corrupt"/"stuck" transform every byte.
    MCU->device traffic passes through untouched.
    """

    inner: object = None
    rules: List[FaultRule] = field(default_factory=list)
    name: str = ""

    _chunk: int = field(default=-1, init=False, repr=False)
    faults_applied: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"faulty:{getattr(self.inner, 'name', 'serial')}"

    def on_rx_from_mcu(self, data: bytes) -> None:
        if hasattr(self.inner, "on_rx_from_mcu"):
            self.inner.on_rx_from_mcu(data)

    def read_tx_to_mcu(self, max_bytes: int = 4096) -> bytes:
        data = self.inner.read_tx_to_mcu(max_bytes) if hasattr(self.inner, "read_tx_to_mcu") else b""
        if not data:
            return data
        self._chunk += 1
        out = bytearray(data)
        for rule in _byte_rules(self.rules):
            if not rule.triggers(self._chunk):
                continue
            if rule.kind == "drop":
                rule.fire()
                self.faults_applied += 1
                return b""
            for i in range(len(out)):
                out[i] = rule.transform_byte(out[i])
            rule.fire()
            self.faults_applied += 1
        return bytes(out)

    def pending_tx_len(self) -> int:
        return self.inner.pending_tx_len() if hasattr(self.inner, "pending_tx_len") else 0

    def tick(self, cycles: int) -> None:
        if hasattr(self.inner, "tick"):
            self.inner.tick(cycles)

    def reset(self) -> None:
        self._chunk = -1
        for r in self.rules:
            r.reset()
        if hasattr(self.inner, "reset"):
            self.inner.reset()

    def snapshot_state(self):
        return self.inner.snapshot_state() if hasattr(self.inner, "snapshot_state") else None

    def restore_state(self, state) -> None:
        if hasattr(self.inner, "restore_state"):
            self.inner.restore_state(state)


__all__ = ["FaultRule", "FaultySpiDevice", "FaultySerialDevice"]
