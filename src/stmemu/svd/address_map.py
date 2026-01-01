from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from stmemu.svd.model import SvdDevice, SvdPeripheral, SvdRegister


@dataclass(frozen=True)
class PeripheralRange:
    name: str
    base: int
    end: int  # exclusive
    peripheral: SvdPeripheral


@dataclass(frozen=True)
class AddressMap:
    device_name: str
    peripherals: tuple[SvdPeripheral, ...]
    ranges: tuple[PeripheralRange, ...]

    def find_peripheral(self, addr: int) -> Optional[SvdPeripheral]:
        # simple linear scan is fine for MVP; upgrade to bisect later
        for r in self.ranges:
            if r.base <= addr < r.end:
                return r.peripheral
        return None

    def find_register(self, p: SvdPeripheral, addr: int) -> Optional[SvdRegister]:
        off = addr - p.base_address
        for reg in p.registers:
            if reg.offset == off:
                return reg
        return None


def build_address_map(device: SvdDevice) -> AddressMap:
    ranges = []
    for p in device.peripherals:
        base = p.base_address
        end = base + max(p.size, 4)
        ranges.append(PeripheralRange(name=p.name, base=base, end=end, peripheral=p))
    ranges.sort(key=lambda r: r.base)
    return AddressMap(device_name=device.name, peripherals=device.peripherals, ranges=tuple(ranges))
