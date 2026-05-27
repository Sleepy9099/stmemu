"""I2C bus connecting the MCU I2C peripheral to external devices."""
from __future__ import annotations

from stmemu.external.i2c_device import I2cDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


class I2cBus:
    """Multi-device I2C bus.

    The MCU I2C peripheral calls into this bus for each transaction
    phase. The bus routes to the device matching the addressed slave.
    """

    def __init__(self, name: str = "i2c0"):
        self.name = name
        self._devices: dict[int, I2cDevice] = {}
        self._active_device: I2cDevice | None = None

    def attach_device(self, device: I2cDevice) -> None:
        self._devices[device.address & 0x7F] = device

    def detach_device(self, address: int) -> bool:
        return self._devices.pop(address & 0x7F, None) is not None

    def devices(self) -> dict[int, I2cDevice]:
        return dict(self._devices)

    def start(self, address: int, read: bool) -> bool:
        """Begin a transaction. Returns True if a device ACKs."""
        addr7 = address & 0x7F
        device = self._devices.get(addr7)
        if device is None:
            self._active_device = None
            return False
        ack = device.start(read)
        if ack:
            self._active_device = device
        else:
            self._active_device = None
        return ack

    def write_byte(self, data: int) -> bool:
        if self._active_device is None:
            return False
        return self._active_device.write_byte(data & 0xFF)

    def read_byte(self) -> int:
        if self._active_device is None:
            return 0xFF
        return self._active_device.read_byte() & 0xFF

    def stop(self) -> None:
        if self._active_device is not None:
            self._active_device.stop()
            self._active_device = None

    def reset(self) -> None:
        self._active_device = None
        for dev in self._devices.values():
            dev.reset()

    def snapshot_state(self) -> object | None:
        states = {}
        for addr, dev in self._devices.items():
            s = dev.snapshot_state()
            if s is not None:
                states[addr] = s
        return {"name": self.name, "device_states": states}

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        ds = state.get("device_states", {})
        for addr_s, dev_state in ds.items():
            addr = int(addr_s)
            dev = self._devices.get(addr)
            if dev is not None:
                dev.restore_state(dev_state)
