from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class FlashPeripheral(GenericRegisterFilePeripheral):
    """FLASH controller with ready-bit simulation.

    Firmware typically sets ACR latency and polls for readiness,
    then may unlock flash for programming via KEYR magic sequence.
    """

    _ACR = 0x00
    _KEYR = 0x04
    _SR = 0x0C
    _CR = 0x10

    _SR_BSY = 1 << 0  # busy flag
    _CR_LOCK = 1 << 31  # lock bit

    _UNLOCK_KEY1 = 0x45670123
    _UNLOCK_KEY2 = 0xCDEF89AB

    _unlock_step: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        # Resolve offsets from SVD if available
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "ACR":
                self._ACR = reg.offset
            elif rname == "KEYR":
                self._KEYR = reg.offset
            elif rname in ("SR", "FLASH_SR"):
                self._SR = reg.offset
            elif rname in ("CR", "FLASH_CR"):
                self._CR = reg.offset

        # Auto-set latency-related ready bits after polling
        for reg in self.peripheral.registers:
            if reg.name.upper() == "ACR":
                for f in reg.fields:
                    if "RDY" in f.name.upper() or "WRHIGHFREQ" in f.name.upper():
                        self.force_bit_after_reads(reg.offset, f.bit_offset, reads_before_set=3)

        # Start locked
        self.write_register_value(self._CR, self.read_register_value(self._CR) | self._CR_LOCK)

    def read(self, offset: int, size: int) -> int:
        if size == 4 and offset == self._SR:
            # BSY is always 0 in emulation (operations complete instantly)
            val = self.read_register_value(self._SR) & ~self._SR_BSY
            self.write_register_value(self._SR, val)
            return val
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._KEYR:
            # Flash unlock sequence: write KEY1 then KEY2
            v = int(value)
            if self._unlock_step == 0 and v == self._UNLOCK_KEY1:
                self._unlock_step = 1
            elif self._unlock_step == 1 and v == self._UNLOCK_KEY2:
                self._unlock_step = 0
                cr = self.read_register_value(self._CR)
                self.write_register_value(self._CR, cr & ~self._CR_LOCK)
            else:
                self._unlock_step = 0
            return

        if size == 4 and offset == self._SR:
            # SR bits are rc_w1 on some families, rc_w0 on others.
            # Clear whichever bits firmware writes.
            current = self.read_register_value(self._SR)
            self.write_register_value(self._SR, current & ~int(value))
            return

        super().write(offset, size, value)

    def reset(self) -> None:
        super().reset()
        self._unlock_step = 0


def build_flash(peripheral: SvdPeripheral) -> FlashPeripheral:
    return FlashPeripheral(peripheral=peripheral)
