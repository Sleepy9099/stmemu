from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

# MODER values
MODE_INPUT = 0
MODE_OUTPUT = 1
MODE_AF = 2
MODE_ANALOG = 3

_MODE_NAMES = {MODE_INPUT: "input", MODE_OUTPUT: "output", MODE_AF: "af", MODE_ANALOG: "analog"}


@dataclass
class GpioPeripheral(GenericRegisterFilePeripheral):
    """GPIO peripheral with BSRR->ODR->IDR linkage and pinmux tracking."""

    _context: PeripheralContext | None = field(default=None, init=False, repr=False)

    _MODER = 0x00
    _OTYPER = 0x04
    _OSPEEDR = 0x08
    _PUPDR = 0x0C
    _IDR = 0x10
    _ODR = 0x14
    _BSRR = 0x18
    _LCKR = 0x1C
    _AFRL = 0x20
    _AFRH = 0x24

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "IDR":
                self._IDR = reg.offset
            elif rname == "ODR":
                self._ODR = reg.offset
            elif rname == "BSRR":
                self._BSRR = reg.offset
            elif rname == "MODER":
                self._MODER = reg.offset
            elif rname == "OTYPER":
                self._OTYPER = reg.offset
            elif rname == "OSPEEDR":
                self._OSPEEDR = reg.offset
            elif rname == "PUPDR":
                self._PUPDR = reg.offset
            elif rname == "AFRL":
                self._AFRL = reg.offset
            elif rname == "AFRH":
                self._AFRH = reg.offset
            elif rname == "LCKR":
                self._LCKR = reg.offset

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def read(self, offset: int, size: int) -> int:
        if size == 4 and offset == self._IDR:
            return self.read_register_value(self._ODR) & 0xFFFF
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._BSRR:
            odr = self.read_register_value(self._ODR)
            set_bits = int(value) & 0xFFFF
            reset_bits = (int(value) >> 16) & 0xFFFF
            odr = (odr | set_bits) & ~reset_bits
            self.write_register_value(self._ODR, odr & 0xFFFF)
            return
        super().write(offset, size, value)

    def pin_mode(self, pin: int) -> int:
        if pin < 0 or pin > 15:
            return 0
        moder = self.read_register_value(self._MODER)
        return (moder >> (pin * 2)) & 0x3

    def pin_mode_name(self, pin: int) -> str:
        return _MODE_NAMES.get(self.pin_mode(pin), "unknown")

    def pin_af(self, pin: int) -> int:
        if pin < 0 or pin > 15:
            return 0
        if pin < 8:
            afr = self.read_register_value(self._AFRL)
            return (afr >> (pin * 4)) & 0xF
        afr = self.read_register_value(self._AFRH)
        return (afr >> ((pin - 8) * 4)) & 0xF

    def pin_otype(self, pin: int) -> int:
        if pin < 0 or pin > 15:
            return 0
        return (self.read_register_value(self._OTYPER) >> pin) & 1

    def pin_pupd(self, pin: int) -> int:
        if pin < 0 or pin > 15:
            return 0
        return (self.read_register_value(self._PUPDR) >> (pin * 2)) & 0x3

    def pin_speed(self, pin: int) -> int:
        if pin < 0 or pin > 15:
            return 0
        return (self.read_register_value(self._OSPEEDR) >> (pin * 2)) & 0x3

    def pin_summary(self, pin: int) -> str:
        mode = self.pin_mode(pin)
        parts = [f"pin{pin}: {self.pin_mode_name(pin)}"]
        if mode == MODE_AF:
            parts.append(f"AF{self.pin_af(pin)}")
        if mode in (MODE_OUTPUT, MODE_AF):
            otype = "OD" if self.pin_otype(pin) else "PP"
            speed = self.pin_speed(pin)
            parts.append(otype)
            parts.append(f"speed={speed}")
        pupd = self.pin_pupd(pin)
        if pupd == 1:
            parts.append("PU")
        elif pupd == 2:
            parts.append("PD")
        return " ".join(parts)

    def port_summary(self) -> str:
        lines = []
        for pin in range(16):
            mode = self.pin_mode(pin)
            if mode != MODE_ANALOG:
                lines.append(self.pin_summary(pin))
        return "\n".join(lines) if lines else "(all analog/reset)"


def build_gpio(peripheral: SvdPeripheral) -> GpioPeripheral:
    return GpioPeripheral(peripheral=peripheral)
