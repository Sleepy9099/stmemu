from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

from stmemu.peripherals.bus import PeripheralModel
from stmemu.utils.bits import mask_for_size

RegisterAccess = Literal["rw", "ro", "wo", "w1c", "w1s"]
ReadHandler = Callable[[int], int]
WriteHandler = Callable[[int, int], int]


@dataclass
class RegisterSpec:
    name: str
    offset: int
    size_bits: int = 32
    reset_value: int = 0
    access: RegisterAccess = "rw"
    on_read: Optional[ReadHandler] = None
    on_write: Optional[WriteHandler] = None

    @property
    def size_bytes(self) -> int:
        return max(1, (self.size_bits + 7) // 8)

    @property
    def value_mask(self) -> int:
        return mask_for_size(self.size_bytes)


class RegisterPeripheral(PeripheralModel):
    def __init__(self, name: str):
        self.name = name
        self._specs: dict[int, RegisterSpec] = {}
        self._values: dict[int, int] = {}

    def reset(self) -> None:
        self._values = {
            spec.offset: int(spec.reset_value) & spec.value_mask
            for spec in self._specs.values()
        }

    def tick(self, cycles: int) -> None:
        del cycles

    def add_register(self, spec: RegisterSpec) -> None:
        self._specs[spec.offset] = spec
        self._values[spec.offset] = int(spec.reset_value) & spec.value_mask

    def register(self, offset: int) -> Optional[RegisterSpec]:
        return self._specs.get(offset)

    def describe(self, offset: int) -> Optional[str]:
        spec = self._find_register(offset, 1)
        return spec.name if spec else None

    def read_register_value(self, offset: int) -> int:
        spec = self._specs.get(offset)
        if spec is None:
            return self._values.get(offset, 0) & 0xFFFFFFFF
        return self._values.get(offset, 0) & spec.value_mask

    def write_register_value(self, offset: int, value: int) -> None:
        spec = self._specs.get(offset)
        if spec is None:
            self._values[offset] = int(value) & 0xFFFFFFFF
            return
        self._values[offset] = int(value) & spec.value_mask

    def read(self, offset: int, size: int) -> int:
        spec = self._find_register(offset, size)
        if spec is None:
            return self._read_synthetic(offset, size)
        return self._read_spec(spec, offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        spec = self._find_register(offset, size)
        if spec is None:
            self._write_synthetic(offset, size, value)
            return
        self._write_spec(spec, offset, size, value)

    def _find_register(self, offset: int, size: int) -> Optional[RegisterSpec]:
        for spec in self._specs.values():
            if spec.offset <= offset and offset + size <= spec.offset + spec.size_bytes:
                return spec
        return None

    def _read_spec(self, spec: RegisterSpec, offset: int, size: int) -> int:
        current = self._values.get(spec.offset, spec.reset_value) & spec.value_mask
        if spec.on_read is not None:
            current = int(spec.on_read(current)) & spec.value_mask
            self._values[spec.offset] = current

        if spec.access == "wo":
            return 0

        shift = (offset - spec.offset) * 8
        return (current >> shift) & mask_for_size(size)

    def _write_spec(self, spec: RegisterSpec, offset: int, size: int, value: int) -> None:
        current = self._values.get(spec.offset, spec.reset_value) & spec.value_mask
        shift = (offset - spec.offset) * 8
        write_mask = mask_for_size(size) << shift
        write_bits = (int(value) & mask_for_size(size)) << shift

        if spec.access == "ro":
            next_value = current
        elif spec.access == "w1c":
            next_value = current & ~(write_bits & write_mask)
        elif spec.access == "w1s":
            next_value = current | (write_bits & write_mask)
        else:
            next_value = (current & ~write_mask) | (write_bits & write_mask)

        if spec.on_write is not None:
            next_value = int(spec.on_write(current, next_value))

        self._values[spec.offset] = next_value & spec.value_mask

    def _read_synthetic(self, offset: int, size: int) -> int:
        slot = offset & ~0x3
        shift = (offset - slot) * 8
        current = self._values.get(slot, 0) & 0xFFFFFFFF
        return (current >> shift) & mask_for_size(size)

    def _write_synthetic(self, offset: int, size: int, value: int) -> None:
        slot = offset & ~0x3
        shift = (offset - slot) * 8
        write_mask = mask_for_size(size) << shift
        current = self._values.get(slot, 0) & 0xFFFFFFFF
        next_value = (current & ~write_mask) | ((int(value) & mask_for_size(size)) << shift)
        self._values[slot] = next_value & 0xFFFFFFFF

    def snapshot_state(self) -> object | None:
        return {"values": {int(k): int(v) for k, v in self._values.items()}}

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        values = state.get("values")
        if not isinstance(values, dict):
            return
        restored: dict[int, int] = {}
        for key, value in values.items():
            try:
                restored[int(key)] = int(value) & 0xFFFFFFFF
            except Exception:
                continue
        self._values = restored
