from __future__ import annotations

from typing import Optional

from stmemu.svd.address_map import AddressMap
from stmemu.utils.logger import get_logger
from dataclasses import dataclass
from typing import Callable, Literal, Optional

log = get_logger(__name__)

AccessType = Literal["r", "w", "rw"]

@dataclass
class MmioWatchpoint:
    wid: int
    label: str
    base: int
    size: int
    access: AccessType = "rw"
    reg_offset: Optional[int] = None  # if set, only match a specific register offset
    enabled: bool = True
    hits: int = 0


class PeripheralModel:
    def read(self, addr: int, size: int) -> int:  # noqa: D401
        """Read from an MMIO address (size in bytes)."""
        raise NotImplementedError

    def write(self, addr: int, size: int, value: int) -> None:  # noqa: D401
        """Write to an MMIO address (size in bytes)."""
        raise NotImplementedError


class PeripheralBus:
    def __init__(self, amap: AddressMap):
        self.amap = amap
        self._models: dict[str, PeripheralModel] = {}
        self.mmio_log_enabled = False

    def register_peripheral(self, name: str, model: PeripheralModel) -> None:
        self._models[name] = model

    def model_for_addr(self, addr: int) -> Optional[PeripheralModel]:
        p = self.amap.find_peripheral(addr)
        if not p:
            return None
        return self._models.get(p.name)

    def read(self, addr: int, size: int) -> int:
        p = self.amap.find_peripheral(addr)
        if not p:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")

        m = self._models.get(p.name)
        if not m:
            raise KeyError(f"no model registered for peripheral {p.name}")

        val = m.read(addr, size)
        if self.mmio_log_enabled:
            reg = self.amap.find_register(p, addr)
            rname = reg.name if reg else f"+0x{addr - p.base_address:X}"
            log.info("MMIO R  %s.%s [0x%08X size=%d] -> 0x%X", p.name, rname, addr, size, val)
        return val

    def write(self, addr: int, size: int, value: int) -> None:
        p = self.amap.find_peripheral(addr)
        if not p:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")

        m = self._models.get(p.name)
        if not m:
            raise KeyError(f"no model registered for peripheral {p.name}")

        if self.mmio_log_enabled:
            reg = self.amap.find_register(p, addr)
            rname = reg.name if reg else f"+0x{addr - p.base_address:X}"
            log.info("MMIO W  %s.%s [0x%08X size=%d] <- 0x%X", p.name, rname, addr, size, value)

        m.write(addr, size, value)
