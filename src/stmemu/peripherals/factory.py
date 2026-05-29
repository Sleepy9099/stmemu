from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from stmemu.peripherals.adc import build_adc
from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.core_cm import CortexMCorePeripheral
from stmemu.peripherals.dma import build_dma
from stmemu.peripherals.dmamux import build_dmamux
from stmemu.peripherals.sdmmc import build_sdmmc
from stmemu.peripherals.flash import build_flash
from stmemu.peripherals.exti import ExtiPeripheral, _DEFAULT_EXTI_IRQS
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.peripherals.gpio import build_gpio
from stmemu.peripherals.rcc import build_rcc
from stmemu.peripherals.i2c import build_i2c
from stmemu.peripherals.memory import RawMemoryPeripheral
from stmemu.peripherals.spi import build_spi
from stmemu.peripherals.timer import build_timer
from stmemu.peripherals.usart import build_usart
from stmemu.peripherals.usb_otg import build_otg_global
from stmemu.svd.address_map import AddressMap
from stmemu.svd.model import SvdPeripheral

PeripheralBuilder = Callable[[SvdPeripheral], PeripheralModel]


# Patterns for auto-detecting peripheral types from SVD names.
# Checked in order; first match wins.
_PERIPHERAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^RCC$", re.IGNORECASE), "rcc"),
    (re.compile(r"^PWR$", re.IGNORECASE), "pwr"),
    (re.compile(r"^ADC\d*$", re.IGNORECASE), "adc"),
    (re.compile(r"^(LPUART|L?P?USART)\d*$", re.IGNORECASE), "usart"),
    (re.compile(r"^UART\d*$", re.IGNORECASE), "usart"),
    (re.compile(r"^TIM\d+$", re.IGNORECASE), "timer"),
    (re.compile(r"^GPIO[A-Z]$", re.IGNORECASE), "gpio"),
    (re.compile(r"^FLASH$", re.IGNORECASE), "flash"),
    (re.compile(r"^SPI\d*$", re.IGNORECASE), "spi"),
    (re.compile(r"^I2C\d*$", re.IGNORECASE), "i2c"),
    (re.compile(r"^DMAMUX\d*$", re.IGNORECASE), "dmamux"),
    (re.compile(r"^DMA\d*$", re.IGNORECASE), "dma"),
    (re.compile(r"^BDMA\d*$", re.IGNORECASE), "dma"),
    (re.compile(r"^SDMMC\d*$", re.IGNORECASE), "sdmmc"),
    (re.compile(r"^OTG\d?_[A-Z]+_GLOBAL$", re.IGNORECASE), "otg_global"),
    (re.compile(r"^USB_OTG_[A-Z]+$", re.IGNORECASE), "otg_global"),
    (re.compile(r"^EXTI$", re.IGNORECASE), "exti"),
]


def _first_irq(peripheral: SvdPeripheral) -> Optional[int]:
    """Return the first interrupt number from SVD data, if any."""
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


@dataclass
class PeripheralFactoryRegistry:
    _builders: dict[str, PeripheralBuilder] = field(default_factory=dict)

    def register(self, peripheral_name: str, builder: PeripheralBuilder) -> None:
        self._builders[peripheral_name.upper()] = builder

    def build(self, peripheral: SvdPeripheral) -> PeripheralModel:
        # Exact name match first
        builder = self._builders.get(peripheral.name.upper())
        if builder is not None:
            return builder(peripheral)

        # Pattern-based fallback
        for pattern, kind in _PERIPHERAL_PATTERNS:
            if pattern.match(peripheral.name):
                builder = self._builders.get(f"__pattern__{kind}".upper())
                if builder is not None:
                    return builder(peripheral)
                break

        return GenericRegisterFilePeripheral(peripheral)


def create_default_registry() -> PeripheralFactoryRegistry:
    registry = PeripheralFactoryRegistry()

    def build_pwr(peripheral: SvdPeripheral) -> PeripheralModel:
        model = GenericRegisterFilePeripheral(peripheral)
        # Firmware commonly polls PWR ready/status bits after voltage scaling
        # writes. Let those bits settle after a few reads, including H7 D3CR.VOSRDY.
        for reg in peripheral.registers:
            for f in reg.fields:
                fname = f.name.upper()
                if "RDY" in fname or "VOF" in fname:
                    model.force_bit_after_reads(reg.offset, f.bit_offset, reads_before_set=10)
        return model

    # Exact name registrations (kept for backward compat, but patterns handle the rest)
    registry.register("RCC", build_rcc)
    registry.register("PWR", build_pwr)

    # Pattern-based builders
    registry.register("__pattern__rcc", build_rcc)
    registry.register("__pattern__pwr", build_pwr)
    registry.register("__pattern__adc", build_adc)
    registry.register("__pattern__usart", build_usart)
    registry.register("__pattern__timer", build_timer)
    registry.register("__pattern__gpio", build_gpio)
    registry.register("__pattern__flash", build_flash)
    registry.register("__pattern__spi", build_spi)
    registry.register("__pattern__i2c", build_i2c)
    registry.register("__pattern__dma", build_dma)
    registry.register("__pattern__dmamux", build_dmamux)
    registry.register("__pattern__sdmmc", build_sdmmc)
    registry.register("__pattern__otg_global", build_otg_global)

    def build_exti(peripheral: SvdPeripheral) -> PeripheralModel:
        irq_map = dict(_DEFAULT_EXTI_IRQS)
        for intr in peripheral.interrupts:
            name = intr.name.upper()
            if "EXTI15_10" in name:
                irq_map[10] = intr.value
            elif "EXTI9_5" in name:
                irq_map[5] = intr.value
            else:
                for i in range(5):
                    if f"EXTI{i}" in name and f"EXTI{i}_" not in name:
                        irq_map[i] = intr.value
        return ExtiPeripheral(irq_map=irq_map)

    registry.register("EXTI", build_exti)
    registry.register("__pattern__exti", build_exti)

    return registry


def _fields_for_offset(peripheral: SvdPeripheral, offset: int):
    """Return fields for the register at the given offset."""
    for reg in peripheral.registers:
        if reg.offset == offset:
            return reg.fields
    return ()


# Well-known system memory base addresses by STM32 family prefix.
_SYSMEM_BASES: dict[str, int] = {
    "STM32H7": 0x1FF1E000,
    "STM32H5": 0x0BF8F000,
    "STM32U5": 0x0BF9F000,
    "STM32L4": 0x1FFF0000,
    "STM32L5": 0x0BF9F000,
    "STM32G0": 0x1FFF0000,
    "STM32G4": 0x1FFF0000,
    "STM32F0": 0x1FFFC400,
    "STM32F1": 0x1FFFF000,
    "STM32F2": 0x1FFF0000,
    "STM32F3": 0x1FFFD800,
    "STM32F4": 0x1FFF0000,
    "STM32F7": 0x1FF00000,
    "STM32WB": 0x1FFF0000,
    "STM32WL": 0x1FFF0000,
}


def _guess_sysmem_base(device_name: str) -> int:
    """Guess system memory base from device name prefix."""
    upper = device_name.upper()
    for prefix, base in _SYSMEM_BASES.items():
        if upper.startswith(prefix):
            return base
    # Default fallback
    return 0x1FFF0000


def build_default_bus(
    amap: AddressMap,
    flash_base: int,
    sysmem_base: Optional[int] = None,
) -> tuple[PeripheralBus, CortexMCorePeripheral]:
    registry = create_default_registry()
    bus = PeripheralBus(amap)
    core = CortexMCorePeripheral(vtor=flash_base)
    bus.set_interrupt_controller(core)

    for peripheral in amap.peripherals:
        model = registry.build(peripheral)
        bus.register_peripheral(peripheral.name, model)
        if peripheral.name.upper() == "RCC":
            bus.set_clock_controller(model)

    bus.mount(
        name=core.name,
        base=CortexMCorePeripheral.PPB_BASE,
        size=CortexMCorePeripheral.PPB_SIZE,
        model=core,
    )

    # System memory page for unique device ID and related readonly data.
    if sysmem_base is None:
        sysmem_base = _guess_sysmem_base(amap.device_name)
    sysmem = bytearray(0x1000)
    uid = bytes.fromhex("01 23 45 67 89 AB CD EF 10 32 54 76")
    sysmem[0x800 : 0x800 + len(uid)] = uid
    bus.mount(
        name="SYSMEM",
        base=sysmem_base,
        size=len(sysmem),
        model=RawMemoryPeripheral(sysmem, readonly=True),
    )
    return bus, core
