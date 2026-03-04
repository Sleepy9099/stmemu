from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class OtgGlobalPeripheral(GenericRegisterFilePeripheral):
    _GRSTCTL = 0x10
    _GRSTCTL_CSRST = 1 << 0
    _GRSTCTL_AHBIDL = 1 << 31

    _reset_reads_remaining: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        # Let USB core reset polling see an idle AHB bus by default.
        self.write_register_value(self._GRSTCTL, self._GRSTCTL_AHBIDL)

    def read(self, offset: int, size: int) -> int:
        if size == 4 and offset == self._GRSTCTL:
            value = self.read_register_value(self._GRSTCTL) | self._GRSTCTL_AHBIDL
            if self._reset_reads_remaining > 0:
                self._reset_reads_remaining -= 1
                value |= self._GRSTCTL_CSRST
            else:
                value &= ~self._GRSTCTL_CSRST
            self.write_register_value(self._GRSTCTL, value)
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._GRSTCTL:
            next_value = int(value) | self._GRSTCTL_AHBIDL
            if int(value) & self._GRSTCTL_CSRST:
                self._reset_reads_remaining = 8
                next_value |= self._GRSTCTL_CSRST
            else:
                self._reset_reads_remaining = 0
                next_value &= ~self._GRSTCTL_CSRST
            self.write_register_value(self._GRSTCTL, next_value)
            return
        super().write(offset, size, value)


def build_otg_global(peripheral: SvdPeripheral) -> OtgGlobalPeripheral:
    return OtgGlobalPeripheral(peripheral=peripheral)
