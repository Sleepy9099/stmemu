from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class GpioPeripheral(GenericRegisterFilePeripheral):
    """GPIO peripheral with BSRR->ODR->IDR linkage.

    Writing BSRR atomically sets/resets bits in ODR.
    Reading IDR reflects the current ODR value (loopback).
    """

    # Standard STM32 GPIO register offsets (consistent across families)
    _MODER = 0x00
    _OTYPER = 0x04
    _OSPEEDR = 0x08
    _PUPDR = 0x0C
    _IDR = 0x10
    _ODR = 0x14
    _BSRR = 0x18
    _LCKR = 0x1C

    def __post_init__(self) -> None:
        super().__post_init__()
        # Resolve offsets from SVD if available (handles variant layouts)
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "IDR":
                self._IDR = reg.offset
            elif rname == "ODR":
                self._ODR = reg.offset
            elif rname == "BSRR":
                self._BSRR = reg.offset

    def read(self, offset: int, size: int) -> int:
        if size == 4 and offset == self._IDR:
            # IDR reflects ODR for output pins (loopback)
            return self.read_register_value(self._ODR) & 0xFFFF
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._BSRR:
            # BSRR: bits[15:0] set ODR bits, bits[31:16] reset ODR bits.
            # Reset takes priority over set for the same bit.
            odr = self.read_register_value(self._ODR)
            set_bits = int(value) & 0xFFFF
            reset_bits = (int(value) >> 16) & 0xFFFF
            odr = (odr | set_bits) & ~reset_bits
            self.write_register_value(self._ODR, odr & 0xFFFF)
            # BSRR is write-only; don't store the value
            return

        super().write(offset, size, value)


def build_gpio(peripheral: SvdPeripheral) -> GpioPeripheral:
    return GpioPeripheral(peripheral=peripheral)
