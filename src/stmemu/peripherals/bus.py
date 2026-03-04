from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Protocol

from stmemu.svd.address_map import AddressMap
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

AccessType = Literal["r", "w", "rw"]


class InterruptController(Protocol):
    def set_irq_pending(self, irq: int, pending: bool = True) -> None:
        ...

    def set_system_pending(self, name: str, pending: bool = True) -> None:
        ...

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
    def read(self, offset: int, size: int) -> int:  # noqa: D401
        """Read from an MMIO offset (size in bytes)."""
        raise NotImplementedError

    def write(self, offset: int, size: int, value: int) -> None:  # noqa: D401
        """Write to an MMIO offset (size in bytes)."""
        raise NotImplementedError

    def reset(self) -> None:
        pass

    def tick(self, cycles: int) -> None:
        del cycles

    def describe(self, offset: int) -> Optional[str]:
        del offset
        return None

    def attach(self, context: "PeripheralContext") -> None:
        del context


@dataclass(frozen=True)
class MountedPeripheral:
    name: str
    base: int
    end: int  # exclusive
    model: PeripheralModel
    peripheral: Optional[SvdPeripheral] = None


@dataclass(frozen=True)
class PeripheralContext:
    name: str
    base: int
    bus: "PeripheralBus"
    interrupts: Optional[InterruptController] = None
    peripheral: Optional[SvdPeripheral] = None


class PeripheralBus:
    def __init__(self, amap: AddressMap):
        self.amap = amap
        self._models: dict[str, PeripheralModel] = {}
        self._mounted: list[MountedPeripheral] = []
        self._interrupts: Optional[InterruptController] = None
        self.mmio_log_enabled = False

    def register_peripheral(self, name: str, model: PeripheralModel) -> None:
        p = self.amap.find_peripheral_by_name(name)
        if p is None:
            raise KeyError(f"unknown peripheral: {name}")
        self.mount(name=p.name, base=p.base_address, size=max(p.size, 4), model=model, peripheral=p)

    def mount(
        self,
        name: str,
        base: int,
        size: int,
        model: PeripheralModel,
        peripheral: Optional[SvdPeripheral] = None,
    ) -> None:
        mounted = MountedPeripheral(
            name=name,
            base=base,
            end=base + max(size, 4),
            model=model,
            peripheral=peripheral,
        )
        self._models[name.upper()] = model
        self._mounted.append(mounted)
        self._mounted.sort(key=lambda item: (item.base, item.end - item.base))
        model.attach(
            PeripheralContext(
                name=name,
                base=base,
                bus=self,
                interrupts=self._interrupts,
                peripheral=peripheral,
            )
        )

    def model_for_addr(self, addr: int) -> Optional[PeripheralModel]:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            return None
        return mounted.model

    def model_for_name(self, name: str) -> Optional[PeripheralModel]:
        return self._models.get(str(name).upper())

    def set_interrupt_controller(self, controller: InterruptController) -> None:
        self._interrupts = controller
        for mounted in self._mounted:
            mounted.model.attach(
                PeripheralContext(
                    name=mounted.name,
                    base=mounted.base,
                    bus=self,
                    interrupts=controller,
                    peripheral=mounted.peripheral,
                )
            )

    def mounted_ranges(self) -> tuple[MountedPeripheral, ...]:
        return tuple(self._mounted)

    def tick(self, cycles: int) -> None:
        seen: set[int] = set()
        for mounted in self._mounted:
            ident = id(mounted.model)
            if ident in seen:
                continue
            seen.add(ident)
            mounted.model.tick(cycles)

    def read(self, addr: int, size: int) -> int:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")
        offset = addr - mounted.base
        val = mounted.model.read(offset, size)
        if self.mmio_log_enabled:
            rname = self._describe_access(mounted, addr)
            log.info("MMIO R  %s.%s [0x%08X size=%d] -> 0x%X", mounted.name, rname, addr, size, val)
        return val

    def write(self, addr: int, size: int, value: int) -> None:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")
        offset = addr - mounted.base
        if self.mmio_log_enabled:
            rname = self._describe_access(mounted, addr)
            log.info("MMIO W  %s.%s [0x%08X size=%d] <- 0x%X", mounted.name, rname, addr, size, value)
        mounted.model.write(offset, size, value)

    def _mount_for_addr(self, addr: int) -> Optional[MountedPeripheral]:
        for mounted in self._mounted:
            if mounted.base <= addr < mounted.end:
                return mounted
        return None

    def _describe_access(self, mounted: MountedPeripheral, addr: int) -> str:
        if mounted.peripheral is not None:
            reg = self.amap.find_register(mounted.peripheral, addr)
            if reg is not None:
                return reg.name
            return f"+0x{addr - mounted.base:X}"

        label = mounted.model.describe(addr - mounted.base)
        if label:
            return label
        return f"+0x{addr - mounted.base:X}"
