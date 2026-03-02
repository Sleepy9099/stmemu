from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.core_cm import CortexMCorePeripheral
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.peripherals.memory import RawMemoryPeripheral
from stmemu.svd.address_map import AddressMap
from stmemu.svd.model import SvdPeripheral

PeripheralBuilder = Callable[[SvdPeripheral], PeripheralModel]


@dataclass
class PeripheralFactoryRegistry:
    _builders: dict[str, PeripheralBuilder] = field(default_factory=dict)

    def register(self, peripheral_name: str, builder: PeripheralBuilder) -> None:
        self._builders[peripheral_name.upper()] = builder

    def build(self, peripheral: SvdPeripheral) -> PeripheralModel:
        builder = self._builders.get(peripheral.name.upper())
        if builder is None:
            return GenericRegisterFilePeripheral(peripheral)
        return builder(peripheral)


def create_default_registry() -> PeripheralFactoryRegistry:
    registry = PeripheralFactoryRegistry()

    def build_rcc(peripheral: SvdPeripheral) -> PeripheralModel:
        model = GenericRegisterFilePeripheral(peripheral)
        model.force_bit_after_reads(0x00, 2, reads_before_set=10)
        model.force_bit_after_reads(0x00, 17, reads_before_set=10)
        model.force_bit_after_reads(0x00, 13, reads_before_set=20)
        model.force_bit_after_reads(0x00, 25, reads_before_set=30)
        model.force_bit_after_reads(0x00, 27, reads_before_set=30)
        model.force_bit_after_reads(0x00, 29, reads_before_set=30)
        model.force_bit_after_reads(0x10, 3, reads_before_set=10)
        model.force_bit_after_reads(0x10, 4, reads_before_set=10)
        return model

    def build_pwr(peripheral: SvdPeripheral) -> PeripheralModel:
        model = GenericRegisterFilePeripheral(peripheral)
        candidate_offsets = {0x04, 0x18}
        for register in peripheral.registers:
            if register.name.upper() in {"CSR", "CSR1"}:
                candidate_offsets.add(register.offset)

        for offset in sorted(candidate_offsets):
            model.force_bit_after_reads(offset, 13, reads_before_set=10)
        return model

    registry.register("RCC", build_rcc)
    registry.register("PWR", build_pwr)
    return registry


def build_default_bus(amap: AddressMap, flash_base: int) -> tuple[PeripheralBus, CortexMCorePeripheral]:
    registry = create_default_registry()
    bus = PeripheralBus(amap)
    core = CortexMCorePeripheral(vtor=flash_base)
    bus.set_interrupt_controller(core)

    for peripheral in amap.peripherals:
        bus.register_peripheral(peripheral.name, registry.build(peripheral))

    bus.mount(
        name=core.name,
        base=CortexMCorePeripheral.PPB_BASE,
        size=CortexMCorePeripheral.PPB_SIZE,
        model=core,
    )

    # STM32H7 system memory page used for unique device ID and related readonly data.
    sysmem = bytearray(0x1000)
    uid = bytes.fromhex("01 23 45 67 89 AB CD EF 10 32 54 76")
    sysmem[0x800 : 0x800 + len(uid)] = uid
    bus.mount(
        name="SYSMEM",
        base=0x1FF1E000,
        size=len(sysmem),
        model=RawMemoryPeripheral(sysmem, readonly=True),
    )
    return bus, core
