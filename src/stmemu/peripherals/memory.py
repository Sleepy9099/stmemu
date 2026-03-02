from __future__ import annotations

from stmemu.peripherals.bus import PeripheralModel
from stmemu.utils.bits import mask_for_size


class RawMemoryPeripheral(PeripheralModel):
    def __init__(self, data: bytes | bytearray, readonly: bool = False):
        self._data = bytearray(data)
        self._readonly = readonly

    def read(self, offset: int, size: int) -> int:
        start = int(offset)
        end = start + int(size)
        if start < 0 or end > len(self._data):
            raise KeyError(f"raw memory read out of range: off=0x{start:X} size={size}")
        return int.from_bytes(self._data[start:end], "little") & mask_for_size(size)

    def write(self, offset: int, size: int, value: int) -> None:
        if self._readonly:
            return
        start = int(offset)
        end = start + int(size)
        if start < 0 or end > len(self._data):
            raise KeyError(f"raw memory write out of range: off=0x{start:X} size={size}")
        self._data[start:end] = int(value).to_bytes(size, "little")
