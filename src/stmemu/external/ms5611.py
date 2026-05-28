"""MS5611 barometric pressure sensor (I2C variant).

The MS5611 has no register file in the conventional sense; commands are
1-byte opcodes that either:

  * Set up an action (RESET, start a pressure or temperature conversion).
  * Latch a 24-bit ADC value the host then clocks out with ADC_READ.
  * Read a 16-bit PROM coefficient (8 of them; calibration data).

Commands:

  0x1E              RESET. Datasheet asks for 2.8 ms before the next
                    command; ignored here (transactions are instant).
  0x40 .. 0x48      D1 (pressure) conversion, OSR 256 / 512 / .. / 4096.
  0x50 .. 0x58      D2 (temperature) conversion, OSR 256 / 512 / .. / 4096.
  0x00              ADC_READ: returns 24 bits (3 bytes, MSB first) of the
                    most recent D1 or D2 value.
  0xA0 .. 0xAE      PROM_READ(addr): returns 16 bits (2 bytes, MSB first)
                    of PROM word ``addr >> 1``. Words 0..7. Word 0 is the
                    factory data / setup, words 1..6 are C1..C6 calibration
                    coefficients, word 7 is the CRC.

This model returns plausible coefficient values so the host's compensation
math does not divide by zero or produce NaNs, and toggles D1/D2 readings
slightly each call so the firmware's "data ready" checks see motion.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.external.i2c_device import I2cDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


_CMD_RESET = 0x1E
_CMD_ADC_READ = 0x00


# Datasheet-typical MS5611 calibration words for a healthy unit at sea
# level / room temp. Word 0 is reserved factory data; word 7 is CRC.
# These were lifted from a real Pixhawk MS5611 reading and produce
# reasonable temperature / pressure when run through the standard
# compensation formula.
_DEFAULT_PROM: tuple[int, ...] = (
    0x0000,  # 0: factory / setup
    0xACAC,  # 1: C1 - pressure sensitivity
    0xA9F3,  # 2: C2 - pressure offset
    0x886D,  # 3: C3 - temperature coefficient of pressure sensitivity
    0x6FBC,  # 4: C4 - temperature coefficient of pressure offset
    0x802A,  # 5: C5 - reference temperature
    0x6F90,  # 6: C6 - temperature coefficient of the temperature
    0x000F,  # 7: CRC (low nibble) -- firmware sometimes ignores
)


@dataclass
class Ms5611I2cDevice(I2cDevice):
    """MS5611 pressure sensor on an I2C bus.

    The chip's I2C address is 0x76 or 0x77 depending on the CSB pin
    strapping. ArduPilot probes both on Pixhawk-class boards.
    """

    address: int = 0x76
    name: str = "ms5611"
    prom: tuple[int, ...] = _DEFAULT_PROM
    base_pressure: int = 0x800000  # 24-bit center, ~near sea level
    base_temperature: int = 0x800000

    _pending_op: str = field(default="", init=False, repr=False)
    _adc_value: int = field(default=0, init=False, repr=False)
    _prom_word: int = field(default=0, init=False, repr=False)
    _read_phase: str = field(default="", init=False, repr=False)
    _read_buf: bytes = field(default=b"", init=False, repr=False)
    _read_idx: int = field(default=0, init=False, repr=False)
    _d1_jitter: int = field(default=0, init=False, repr=False)
    _d2_jitter: int = field(default=0, init=False, repr=False)
    _commands: int = field(default=0, init=False, repr=False)
    _reads: int = field(default=0, init=False, repr=False)

    def start(self, read: bool) -> bool:
        if read:
            self._prime_read_buffer()
        return True

    def write_byte(self, data: int) -> bool:
        cmd = data & 0xFF
        self._commands += 1

        if cmd == _CMD_RESET:
            self._pending_op = ""
            self._adc_value = 0
            self._read_phase = ""
            return True

        if cmd == _CMD_ADC_READ:
            # The host will issue a repeated-start + read transaction next;
            # latch the ADC value so _prime_read_buffer returns it.
            self._read_phase = "adc"
            return True

        if 0x40 <= cmd <= 0x48:
            self._pending_op = "d1"
            self._d1_jitter = (self._d1_jitter + 1) & 0x1F
            self._adc_value = (self.base_pressure + self._d1_jitter) & 0xFFFFFF
            return True

        if 0x50 <= cmd <= 0x58:
            self._pending_op = "d2"
            self._d2_jitter = (self._d2_jitter + 1) & 0x1F
            self._adc_value = (self.base_temperature + self._d2_jitter) & 0xFFFFFF
            return True

        if 0xA0 <= cmd <= 0xAE and (cmd & 1) == 0:
            word_idx = (cmd - 0xA0) >> 1
            if word_idx < len(self.prom):
                self._prom_word = self.prom[word_idx] & 0xFFFF
            else:
                self._prom_word = 0x0000
            self._read_phase = "prom"
            return True

        # Unknown command: ack but ignore.
        return True

    def read_byte(self) -> int:
        if self._read_idx < len(self._read_buf):
            byte = self._read_buf[self._read_idx]
            self._read_idx += 1
            self._reads += 1
            return byte
        return 0xFF

    def stop(self) -> None:
        self._read_phase = ""
        self._read_buf = b""
        self._read_idx = 0

    # ── Helpers ────────────────────────────────────────────────────

    def _prime_read_buffer(self) -> None:
        if self._read_phase == "prom":
            self._read_buf = bytes([
                (self._prom_word >> 8) & 0xFF,
                self._prom_word & 0xFF,
            ])
        elif self._read_phase == "adc":
            value = self._adc_value & 0xFFFFFF
            self._read_buf = bytes([
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ])
        else:
            self._read_buf = b"\xFF\xFF\xFF"
        self._read_idx = 0

    # ── Persistence / inspection ──────────────────────────────────

    def stats(self) -> dict[str, int]:
        return {
            "commands": self._commands,
            "reads": self._reads,
            "address": self.address,
            "last_adc": self._adc_value,
        }

    def reset(self) -> None:
        super().reset()
        self._pending_op = ""
        self._adc_value = 0
        self._prom_word = 0
        self._read_phase = ""
        self._read_buf = b""
        self._read_idx = 0
        self._d1_jitter = 0
        self._d2_jitter = 0

    def snapshot_state(self) -> object | None:
        return {
            "pending_op": self._pending_op,
            "adc_value": self._adc_value,
            "prom_word": self._prom_word,
            "read_phase": self._read_phase,
            "read_buf": bytes(self._read_buf),
            "read_idx": self._read_idx,
            "d1_jitter": self._d1_jitter,
            "d2_jitter": self._d2_jitter,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        self._pending_op = str(state.get("pending_op", ""))
        self._adc_value = int(state.get("adc_value", 0)) & 0xFFFFFF
        self._prom_word = int(state.get("prom_word", 0)) & 0xFFFF
        self._read_phase = str(state.get("read_phase", ""))
        raw = state.get("read_buf", b"")
        if isinstance(raw, (bytes, bytearray)):
            self._read_buf = bytes(raw)
        self._read_idx = int(state.get("read_idx", 0))
        self._d1_jitter = int(state.get("d1_jitter", 0)) & 0x1F
        self._d2_jitter = int(state.get("d2_jitter", 0)) & 0x1F


__all__ = ["Ms5611I2cDevice"]
