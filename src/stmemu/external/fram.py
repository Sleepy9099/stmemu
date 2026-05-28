"""Cypress/Infineon FM25V02A 256-Kbit SPI Ferroelectric RAM device model.

The FM25V02A is a 32 KiB (256 Kbit) F-RAM with a standard SPI command set:

  Opcode  Command         Description
  0x06    WREN            Set Write Enable Latch
  0x04    WRDI            Reset Write Enable Latch
  0x05    RDSR            Read Status Register (1 dummy + 1 byte status)
  0x01    WRSR            Write Status Register (1 byte)
  0x03    READ            Read memory (16-bit address + N data bytes)
  0x0B    FSTRD           Fast Read (16-bit address + 1 dummy + N data)
  0x02    WRITE           Write memory (16-bit address + N data bytes)
  0x9F    RDID            Read JEDEC ID (9 ID bytes)
  0xC3    SNR             Read serial number (8 bytes)
  0xB9    SLEEP           Enter sleep mode

The device is selected by an active-low CS pin (a GPIO line on the MCU).
CS state is tracked via ``gpio_edge`` events emitted by the GPIO peripheral.
A falling edge starts a new command frame; a rising edge ends it and the
internal state machine returns to idle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from stmemu.external.device import ExternalDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


# JEDEC ID returned in response to RDID (0x9F).
#
# Datasheet behavior (Cypress/Infineon revision) is six 0x7F continuation
# bytes followed by manufacturer 0xC2 (Cypress bank 7), family 0x22, and
# density 0x08. Real ArduPilot AP_RAMTRON drivers shipped against the
# original Ramtron part though, and only recognize the four-byte
# Ramtron-era response: 0x7F 0x03 0x22 0x00. We default to that pattern so
# unmodified firmware identifies the chip.
FM25V02A_JEDEC = bytes([0x7F, 0x03, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

FM25V02A_SIZE = 32 * 1024  # 32 KiB

# Default serial number — arbitrary but stable. Pixhawk firmware sometimes uses
# this to identify the storage chip across reboots.
_DEFAULT_SNR = bytes([0xA5, 0xB6, 0xC7, 0xD8, 0xE9, 0xFA, 0x0B, 0x1C])


# Status register bits the FM25V02A actually honors:
#   bit 1 WEL  — read-only mirror of write-enable latch
#   bit 2 BP0  — block protect 0
#   bit 3 BP1  — block protect 1
#   bit 7 WPEN — write protect enable
_SR_WEL = 0x02
_SR_BP_MASK = 0x0C
_SR_WPEN = 0x80
_SR_WRITABLE_MASK = _SR_BP_MASK | _SR_WPEN


@dataclass
class FramFm25v02a(ExternalDevice):
    """FM25V02A 32 KiB SPI F-RAM with optional file-backed persistence.

    The state machine assumes CS edges delimit commands. ``cs_release()``
    resets the per-command state — connect it to a GPIO falling/rising
    edge handler when wiring this device into a board.
    """

    name: str = "fm25v02a"
    image_path: Optional[Path] = None
    serial_number: bytes = field(default_factory=lambda: bytes(_DEFAULT_SNR))
    _mem: bytearray = field(default_factory=lambda: bytearray(FM25V02A_SIZE), init=False, repr=False)
    _wel: bool = field(default=False, init=False, repr=False)
    _status_reg: int = field(default=0, init=False, repr=False)
    _cs_active: bool = field(default=False, init=False, repr=False)
    _state: str = field(default="IDLE", init=False, repr=False)
    _cmd: int = field(default=0, init=False, repr=False)
    _addr: int = field(default=0, init=False, repr=False)
    _addr_bytes: int = field(default=0, init=False, repr=False)
    _data_index: int = field(default=0, init=False, repr=False)
    _writes_total: int = field(default=0, init=False, repr=False)
    _reads_total: int = field(default=0, init=False, repr=False)
    _commands_total: int = field(default=0, init=False, repr=False)
    _bytes_exchanged: int = field(default=0, init=False, repr=False)
    _recent_mosi: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _recent_miso: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _dirty: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.image_path is not None and self.image_path.exists():
            data = self.image_path.read_bytes()
            n = min(len(data), FM25V02A_SIZE)
            self._mem[:n] = data[:n]
            log.info("fram: loaded %d bytes from %s", n, self.image_path)

    # ── CS handling (called by an external GPIO edge listener) ─────

    def cs_select(self) -> None:
        """CS asserted (falling edge). Begin a new command frame."""
        self._cs_active = True
        self._state = "IDLE"
        self._cmd = 0
        self._addr = 0
        self._addr_bytes = 0
        self._data_index = 0

    def cs_release(self) -> None:
        """CS deasserted (rising edge). End the current command frame."""
        self._cs_active = False
        # Per the FM25V02A datasheet, WEL is cleared after a WRITE / WRSR
        # transaction completes. Other commands leave WEL untouched.
        if self._cmd in (0x02, 0x01):
            self._wel = False
        self._state = "IDLE"

    # ── Per-byte exchange driven by the SPI peripheral ─────────────

    def exchange(self, mosi: int) -> int:
        """Clock one byte: take MOSI, return MISO."""
        mosi &= 0xFF
        miso = self._exchange_inner(mosi)
        self._bytes_exchanged += 1
        self._recent_mosi.append(mosi)
        self._recent_miso.append(miso & 0xFF)
        if len(self._recent_mosi) > 64:
            del self._recent_mosi[:-64]
            del self._recent_miso[:-64]
        return miso

    def _exchange_inner(self, mosi: int) -> int:

        # If we never saw a CS-falling edge (e.g. board lacks a wired CS or
        # the firmware drove CS through the hardware NSS pin), treat each
        # byte arrival as still part of an ongoing frame and rely on
        # per-command state to advance.
        if self._state == "IDLE":
            return self._begin_command(mosi)

        if self._state == "RDSR_DATA":
            # Datasheet: dummy byte is the RDSR opcode itself; subsequent
            # clock cycles return the status. Keep returning status for as
            # long as the host keeps clocking.
            return self._status_byte()

        if self._state == "WRSR_DATA":
            if self._wel:
                self._status_reg = mosi & _SR_WRITABLE_MASK
                self._wel = False
            self._state = "COMPLETE"
            return 0xFF

        if self._state == "ADDR":
            self._addr = ((self._addr << 8) | mosi) & 0xFFFF
            self._addr_bytes += 1
            if self._addr_bytes >= 2:
                if self._cmd == 0x03:        # READ
                    self._state = "READ_DATA"
                elif self._cmd == 0x02:      # WRITE
                    self._state = "WRITE_DATA"
                elif self._cmd == 0x0B:      # FSTRD: one dummy then data
                    self._state = "FSTRD_DUMMY"
                else:
                    self._state = "COMPLETE"
            return 0xFF

        if self._state == "FSTRD_DUMMY":
            self._state = "READ_DATA"
            return 0xFF

        if self._state == "READ_DATA":
            offset = self._addr & (FM25V02A_SIZE - 1)
            byte = self._mem[offset]
            self._addr = (self._addr + 1) & 0xFFFF
            self._reads_total += 1
            return byte

        if self._state == "WRITE_DATA":
            if self._wel:
                offset = self._addr & (FM25V02A_SIZE - 1)
                self._mem[offset] = mosi
                self._addr = (self._addr + 1) & 0xFFFF
                self._writes_total += 1
                self._dirty = True
            return 0xFF

        if self._state == "RDID_DATA":
            if self._data_index < len(FM25V02A_JEDEC):
                byte = FM25V02A_JEDEC[self._data_index]
                self._data_index += 1
                return byte
            return 0xFF

        if self._state == "SNR_DATA":
            if self._data_index < len(self.serial_number):
                byte = self.serial_number[self._data_index]
                self._data_index += 1
                return byte
            return 0xFF

        # COMPLETE / unknown: ignore further bytes until next CS edge.
        return 0xFF

    def _begin_command(self, mosi: int) -> int:
        self._cmd = mosi
        self._commands_total += 1

        if mosi == 0x06:        # WREN
            self._wel = True
            self._state = "COMPLETE"
            return 0xFF
        if mosi == 0x04:        # WRDI
            self._wel = False
            self._state = "COMPLETE"
            return 0xFF
        if mosi == 0x05:        # RDSR
            self._state = "RDSR_DATA"
            return 0xFF
        if mosi == 0x01:        # WRSR
            self._state = "WRSR_DATA"
            return 0xFF
        if mosi in (0x03, 0x02, 0x0B):  # READ / WRITE / FSTRD
            self._addr = 0
            self._addr_bytes = 0
            self._state = "ADDR"
            return 0xFF
        if mosi == 0x9F:        # RDID
            self._data_index = 0
            self._state = "RDID_DATA"
            return 0xFF
        if mosi == 0xC3:        # SNR
            self._data_index = 0
            self._state = "SNR_DATA"
            return 0xFF
        if mosi == 0xB9:        # SLEEP
            self._state = "COMPLETE"
            return 0xFF
        # Unknown opcode — silently consume the frame.
        self._state = "COMPLETE"
        return 0xFF

    def _status_byte(self) -> int:
        sr = self._status_reg & _SR_WRITABLE_MASK
        if self._wel:
            sr |= _SR_WEL
        return sr & 0xFF

    # ── Persistence ───────────────────────────────────────────────

    def save_image(self, path: Optional[Path] = None) -> Path:
        """Persist FRAM contents to disk. Returns the path written."""
        out = Path(path) if path is not None else self.image_path
        if out is None:
            raise ValueError("no image path configured")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(bytes(self._mem))
        self._dirty = False
        log.info("fram: saved %d bytes to %s", len(self._mem), out)
        return out

    # ── Inspection helpers (used by the shell ``device status``) ─

    def stats(self) -> dict[str, int | str]:
        return {
            "commands": self._commands_total,
            "reads": self._reads_total,
            "writes": self._writes_total,
            "bytes": self._bytes_exchanged,
            "state": self._state,
            "wel": int(self._wel),
            "status_reg": self._status_byte(),
            "dirty": int(self._dirty),
            "size": FM25V02A_SIZE,
            "recent_mosi": bytes(self._recent_mosi).hex(),
            "recent_miso": bytes(self._recent_miso).hex(),
        }

    def memory(self) -> bytes:
        return bytes(self._mem)

    def poke(self, offset: int, data: bytes) -> None:
        offset &= 0xFFFF
        end = min(offset + len(data), FM25V02A_SIZE)
        n = end - offset
        if n > 0:
            self._mem[offset:end] = data[:n]
            self._dirty = True

    # ── ExternalDevice / snapshot interface ──────────────────────

    def reset(self) -> None:
        self._mem[:] = b"\x00" * FM25V02A_SIZE
        self._wel = False
        self._status_reg = 0
        self.cs_release()
        self._writes_total = 0
        self._reads_total = 0
        self._commands_total = 0
        self._dirty = False

    def snapshot_state(self) -> object | None:
        return {
            "mem": bytes(self._mem),
            "wel": self._wel,
            "status_reg": self._status_reg,
            "cs_active": self._cs_active,
            "state": self._state,
            "cmd": self._cmd,
            "addr": self._addr,
            "addr_bytes": self._addr_bytes,
            "data_index": self._data_index,
            "writes_total": self._writes_total,
            "reads_total": self._reads_total,
            "commands_total": self._commands_total,
            "dirty": self._dirty,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        mem = state.get("mem")
        if isinstance(mem, (bytes, bytearray)) and len(mem) == FM25V02A_SIZE:
            self._mem[:] = bytes(mem)
        self._wel = bool(state.get("wel", False))
        self._status_reg = int(state.get("status_reg", 0)) & 0xFF
        self._cs_active = bool(state.get("cs_active", False))
        self._state = str(state.get("state", "IDLE"))
        self._cmd = int(state.get("cmd", 0)) & 0xFF
        self._addr = int(state.get("addr", 0)) & 0xFFFF
        self._addr_bytes = int(state.get("addr_bytes", 0))
        self._data_index = int(state.get("data_index", 0))
        self._writes_total = int(state.get("writes_total", 0))
        self._reads_total = int(state.get("reads_total", 0))
        self._commands_total = int(state.get("commands_total", 0))
        self._dirty = bool(state.get("dirty", False))
