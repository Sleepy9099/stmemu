"""Base class and common devices for I2C bus."""
from __future__ import annotations

from dataclasses import dataclass, field


class I2cDevice:
    """Protocol for a device on an I2C bus.

    Devices are addressed by 7-bit address. Transactions are:
      write: address(W) + register + data bytes
      read:  address(W) + register, then address(R) + read N bytes
    """

    address: int = 0x00
    name: str = "i2c_device"

    def start(self, read: bool) -> bool:
        """Called on START+address. Return True to ACK, False to NACK."""
        return True

    def write_byte(self, data: int) -> bool:
        """Called for each byte in a write transaction. Return True to ACK."""
        return True

    def read_byte(self) -> int:
        """Return next byte for a read transaction."""
        return 0xFF

    def stop(self) -> None:
        """Called on STOP condition."""
        pass

    def reset(self) -> None:
        pass

    def snapshot_state(self) -> object | None:
        return None

    def restore_state(self, state: object) -> None:
        del state


@dataclass
class RegisterI2cDevice(I2cDevice):
    """I2C device with a flat register file.

    First byte after address-write sets the register pointer.
    Subsequent writes store data sequentially. Reads return
    sequential register values from the pointer.
    """

    address: int = 0x50
    name: str = "reg_device"
    _registers: bytearray = field(default_factory=lambda: bytearray(256), init=False, repr=False)
    _pointer: int = field(default=0, init=False, repr=False)
    _pointer_set: bool = field(default=False, init=False, repr=False)

    def set_register(self, reg: int, value: int) -> None:
        if 0 <= reg < len(self._registers):
            self._registers[reg] = value & 0xFF

    def get_register(self, reg: int) -> int:
        if 0 <= reg < len(self._registers):
            return self._registers[reg]
        return 0

    def start(self, read: bool) -> bool:
        if read:
            self._pointer_set = True
        else:
            self._pointer_set = False
        return True

    def write_byte(self, data: int) -> bool:
        if not self._pointer_set:
            self._pointer = data & 0xFF
            self._pointer_set = True
        else:
            if self._pointer < len(self._registers):
                self._registers[self._pointer] = data & 0xFF
            self._pointer = (self._pointer + 1) & 0xFF
        return True

    def read_byte(self) -> int:
        val = self.get_register(self._pointer)
        self._pointer = (self._pointer + 1) & 0xFF
        return val

    def stop(self) -> None:
        pass

    def reset(self) -> None:
        self._registers[:] = b"\x00" * len(self._registers)
        self._pointer = 0
        self._pointer_set = False

    def snapshot_state(self) -> object | None:
        return {
            "registers": bytes(self._registers),
            "pointer": self._pointer,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        regs = state.get("registers")
        if isinstance(regs, (bytes, bytearray)):
            self._registers[:len(regs)] = regs[:len(self._registers)]
        self._pointer = int(state.get("pointer", 0))


@dataclass
class EepromI2cDevice(RegisterI2cDevice):
    """Simple I2C EEPROM (256 bytes)."""
    address: int = 0x50
    name: str = "eeprom"


@dataclass
class ImuI2cDevice(RegisterI2cDevice):
    """Simple IMU stub with WHOAMI register."""
    address: int = 0x68
    name: str = "imu"
    whoami_reg: int = 0x75
    whoami_value: int = 0x71

    def __post_init__(self) -> None:
        self.set_register(self.whoami_reg, self.whoami_value)

    def reset(self) -> None:
        super().reset()
        self.set_register(self.whoami_reg, self.whoami_value)
