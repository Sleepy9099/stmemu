"""SPI device models for on-board inertial sensors.

These speak the standard "address byte + data byte(s)" wire format used by
the TDK/Invensense and Bosch parts the ArduPilot HAL probes during init.
They are intentionally minimal: enough register state to make WHOAMI reads
succeed and let configuration writes round-trip, so the driver's probe
sequence (set bank, write config, verify) does not bail out before reading
sensor data.

State machine
-------------
Each device tracks a single transaction (CS asserted -> CS released):

  IDLE   : first byte after CS-fall is the address+RW byte. We split it
           into a 7-bit register address and a read flag (Bosch/Invensense
           convention: bit 7 set = read).
  ARGS   : optional dummy byte(s) some chips insert after the address
           before real data flows.
  DATA   : every subsequent byte either reads or writes ``_registers[reg]``
           with auto-increment.

When CS goes high we reset to IDLE. A device with no CS wired stays in
DATA forever, but for our purposes the firmware always drives CS via GPIO.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.external.device import ExternalDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class _SpiRegisterDevice(ExternalDevice):
    """Common register-file SPI slave with CS tracking and access counters.

    Subclasses tune ``read_dummy_bytes`` (Bosch accel inserts one between
    the address byte and the first data byte) and pre-populate
    ``_registers`` with WHOAMI / configuration defaults.
    """

    name: str = "spi_dev"
    register_count: int = 256
    read_dummy_bytes: int = 0
    cs_active: bool = field(default=False, init=False, repr=False)
    _registers: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _state: str = field(default="IDLE", init=False, repr=False)
    _is_read: bool = field(default=False, init=False, repr=False)
    _reg_ptr: int = field(default=0, init=False, repr=False)
    _dummies_remaining: int = field(default=0, init=False, repr=False)
    _reads: int = field(default=0, init=False, repr=False)
    _writes: int = field(default=0, init=False, repr=False)
    _commands: int = field(default=0, init=False, repr=False)
    _bytes_exchanged: int = field(default=0, init=False, repr=False)
    _recent_mosi: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _recent_miso: bytearray = field(default_factory=bytearray, init=False, repr=False)
    # FIFO streaming: reading ``_fifo_data_reg`` yields successive bytes of a
    # repeating sample frame (``_fifo_frame``) instead of a single register,
    # and the register pointer does NOT auto-increment — matching how a real
    # IMU streams its FIFO out of one data register. ``-1`` disables it.
    _fifo_data_reg: int = field(default=-1, init=False, repr=False)
    _fifo_frame: bytes = field(default=b"", init=False, repr=False)
    _stream_pos: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self._registers:
            self._registers = bytearray(self.register_count)
        self._apply_defaults()

    # Hook for subclasses to set WHOAMI / power-on register values.
    def _apply_defaults(self) -> None:
        pass

    # ── CS handling ────────────────────────────────────────────────

    def cs_select(self) -> None:
        self.cs_active = True
        self._state = "IDLE"
        self._is_read = False
        self._reg_ptr = 0
        self._dummies_remaining = 0
        # Each FIFO burst is a fresh CS transaction that begins on a frame
        # boundary, so realign the streaming sample pattern here.
        self._stream_pos = 0

    def cs_release(self) -> None:
        self.cs_active = False
        self._state = "IDLE"

    # ── Per-byte exchange ──────────────────────────────────────────

    def exchange(self, mosi: int) -> int:
        mosi &= 0xFF
        miso = self._dispatch(mosi)
        self._bytes_exchanged += 1
        self._recent_mosi.append(mosi)
        self._recent_miso.append(miso & 0xFF)
        if len(self._recent_mosi) > 32:
            del self._recent_mosi[:-32]
            del self._recent_miso[:-32]
        return miso

    def _dispatch(self, mosi: int) -> int:
        if self._state == "IDLE":
            self._commands += 1
            self._is_read = bool(mosi & 0x80)
            self._reg_ptr = mosi & 0x7F
            if self._is_read and self.read_dummy_bytes > 0:
                self._dummies_remaining = self.read_dummy_bytes
                self._state = "DUMMY"
            else:
                self._state = "DATA"
            return 0xFF

        if self._state == "DUMMY":
            self._dummies_remaining -= 1
            if self._dummies_remaining <= 0:
                self._state = "DATA"
            return 0xFF

        if self._state == "DATA":
            if self._is_read:
                if self._reg_ptr == self._fifo_data_reg and self._fifo_frame:
                    # Streaming FIFO data register: clock out the next byte of
                    # a repeating sample frame; the pointer stays put so the
                    # whole burst drains from this one register.
                    frame = self._fifo_frame
                    value = frame[self._stream_pos % len(frame)]
                    self._stream_pos += 1
                    self._reads += 1
                    return value
                value = self._read_register(self._reg_ptr)
                self._reads += 1
            else:
                self._write_register(self._reg_ptr, mosi)
                self._writes += 1
                value = 0xFF
            self._reg_ptr = (self._reg_ptr + 1) & 0x7F
            return value

        return 0xFF

    # ── Register helpers (override for banked / virtual regs) ─────

    def _read_register(self, reg: int) -> int:
        if 0 <= reg < len(self._registers):
            return self._registers[reg]
        return 0xFF

    def _write_register(self, reg: int, value: int) -> None:
        if 0 <= reg < len(self._registers):
            self._registers[reg] = value & 0xFF

    # ── Inspection / persistence ───────────────────────────────────

    def stats(self) -> dict[str, int | str]:
        return {
            "commands": self._commands,
            "reads": self._reads,
            "writes": self._writes,
            "bytes": self._bytes_exchanged,
            "state": self._state,
            "cs_active": int(self.cs_active),
            "recent_mosi": bytes(self._recent_mosi).hex(),
            "recent_miso": bytes(self._recent_miso).hex(),
        }

    def snapshot_state(self) -> object | None:
        return {
            "registers": bytes(self._registers),
            "cs_active": self.cs_active,
            "state": self._state,
            "is_read": self._is_read,
            "reg_ptr": self._reg_ptr,
            "dummies_remaining": self._dummies_remaining,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        regs = state.get("registers")
        if isinstance(regs, (bytes, bytearray)) and len(regs) == len(self._registers):
            self._registers[:] = bytes(regs)
        self.cs_active = bool(state.get("cs_active", False))
        self._state = str(state.get("state", "IDLE"))
        self._is_read = bool(state.get("is_read", False))
        self._reg_ptr = int(state.get("reg_ptr", 0)) & 0x7F
        self._dummies_remaining = int(state.get("dummies_remaining", 0))


# ── ICM-42688-P (TDK Invensense) ───────────────────────────────────


_ICM42688_WHOAMI = 0x47


@dataclass
class Icm42688Device(_SpiRegisterDevice):
    """TDK ICM-42688-P 6-axis IMU.

    WHOAMI lives at register 0x75 (bank 0) and returns 0x47. The device
    has multiple register banks selected via REG_BANK_SEL at 0x76, but
    AP_InertialSensor_Invensensev3's probe only inspects bank 0 to
    identify the part, so the bank latch is acknowledged but ignored.
    """

    name: str = "icm42688"
    register_count: int = 128
    read_dummy_bytes: int = 0  # ICM-42688 has no dummy byte for reads

    _REG_WHOAMI = 0x75
    _REG_BANK_SEL = 0x76
    # FIFO (bank 0): COUNTH/COUNTL report records available, DATA streams them.
    _REG_FIFO_COUNTH = 0x2E
    _REG_FIFO_COUNTL = 0x2F
    _REG_FIFO_DATA = 0x30
    # Records reported per read; <= INV3_FIFO_BUFFER_LEN (8) so the driver
    # drains the whole FIFO in a single SPI burst.
    _FIFO_RECORDS = 8

    def _apply_defaults(self) -> None:
        self._registers[self._REG_WHOAMI] = _ICM42688_WHOAMI
        # Stream 16-byte FIFOData frames: header 0x68 (ACCEL_EN|GYRO_EN|
        # TMST_FIELD_EN, validated via (header & 0xFC)==0x68), zero gyro, and
        # +1g on accel Z so the AHRS/EKF have a gravity vector to initialise
        # attitude (raw 2048 @ 16g scale = 9.81 m/s^2). Layout: header(1),
        # accel xyz int16 LE (6), gyro xyz (6), temp(1), timestamp(2).
        self._fifo_data_reg = self._REG_FIFO_DATA
        self._fifo_frame = bytes([0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08]) + bytes(9)

    def _read_register(self, reg: int) -> int:
        # Constant FIFO depth, little-endian count in records (INTF_CONFIG0=
        # 0xC0). Forced here so stray bank writes on these offsets can't
        # corrupt the count the driver reads back.
        if reg == self._REG_FIFO_COUNTH:
            return self._FIFO_RECORDS & 0xFF
        if reg == self._REG_FIFO_COUNTL:
            return (self._FIFO_RECORDS >> 8) & 0xFF
        return super()._read_register(reg)


# ── BMI088 (Bosch) ─────────────────────────────────────────────────


_BMI088_ACCEL_WHOAMI = 0x1E
_BMI088_GYRO_WHOAMI = 0x0F


@dataclass
class Bmi088AccelDevice(_SpiRegisterDevice):
    """Bosch BMI088 accelerometer half.

    Quirk: on a READ, the first byte clocked out after the address is a
    dummy (datasheet "Bosch SPI read"). We mark this with
    ``read_dummy_bytes = 1`` so the base state machine inserts it.

    WHOAMI at reg 0x00 = 0x1E.
    """

    name: str = "bmi088_a"
    register_count: int = 128
    read_dummy_bytes: int = 1

    _REG_CHIP_ID = 0x00
    _REG_ACC_STATUS = 0x03
    _REG_FIFO_LEN0 = 0x24
    _REG_FIFO_LEN1 = 0x25
    _REG_FIFO_DATA = 0x26
    # Accel frames available per read; 6*7 = 42 bytes < the driver's 8*7 cap.
    _FIFO_FRAMES = 6

    def _apply_defaults(self) -> None:
        self._registers[self._REG_CHIP_ID] = _BMI088_ACCEL_WHOAMI
        # Data-ready bit set so firmware doesn't hang on the status poll.
        self._registers[self._REG_ACC_STATUS] = 0x80
        # Stream variable-length FIFO frames; 0x84 marks a 7-byte accel frame
        # (header + int16 x/y/z). +1g on Z (raw 1366 @ 24g range = 9.81 m/s^2)
        # gives the AHRS/EKF a gravity vector; constant, so it never trips the
        # gyro-cal "platform moved" guard (accel_diff < 0.2).
        self._fifo_data_reg = self._REG_FIFO_DATA
        self._fifo_frame = bytes([0x84, 0x00, 0x00, 0x00, 0x00, 0x56, 0x05])

    def _read_register(self, reg: int) -> int:
        # FIFO byte length = frames * 7, LSB then MSB; top bit clear = data.
        if reg == self._REG_FIFO_LEN0:
            return (self._FIFO_FRAMES * 7) & 0xFF
        if reg == self._REG_FIFO_LEN1:
            return ((self._FIFO_FRAMES * 7) >> 8) & 0xFF
        return super()._read_register(reg)


@dataclass
class Bmi088GyroDevice(_SpiRegisterDevice):
    """Bosch BMI088 gyroscope half.

    No read-dummy quirk on the gyro side (only the accel inserts one).
    WHOAMI at reg 0x00 = 0x0F.
    """

    name: str = "bmi088_g"
    register_count: int = 128
    read_dummy_bytes: int = 0

    _REG_CHIP_ID = 0x00
    _REG_FIFO_STATUS = 0x0E
    _REG_FIFO_DATA = 0x3F
    # Frames available per read; driver caps at 8. Top bit (0x80) = overrun.
    _FIFO_FRAMES = 8

    def _apply_defaults(self) -> None:
        self._registers[self._REG_CHIP_ID] = _BMI088_GYRO_WHOAMI
        # Stream 6-byte frames (int16 x/y/z) of zero angular rate so the gyro
        # calibration sees a perfectly still sensor and converges at once.
        self._fifo_data_reg = self._REG_FIFO_DATA
        self._fifo_frame = bytes(6)

    def _read_register(self, reg: int) -> int:
        if reg == self._REG_FIFO_STATUS:
            return self._FIFO_FRAMES & 0x7F
        return super()._read_register(reg)


__all__ = [
    "Icm42688Device",
    "Bmi088AccelDevice",
    "Bmi088GyroDevice",
]
