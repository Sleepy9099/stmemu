from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class Stm32AdcPeripheral(GenericRegisterFilePeripheral):
    _cr_offset: int | None = field(default=None, init=False, repr=False)
    _isr_offset: int | None = field(default=None, init=False, repr=False)
    _calibration_reads_remaining: int = field(default=0, init=False, repr=False)

    _CR_ADEN = 1 << 0
    _CR_ADCAL = 1 << 31
    _ISR_ADRDY = 1 << 0

    def __post_init__(self) -> None:
        super().__post_init__()
        for register in self.peripheral.registers:
            name = register.name.upper()
            if name == "CR":
                self._cr_offset = register.offset
            elif name == "ISR":
                self._isr_offset = register.offset

    def write(self, offset: int, size: int, value: int) -> None:
        super().write(offset, size, value)
        if size != 4 or self._cr_offset is None or offset != self._cr_offset:
            return

        control = self.read_register_value(self._cr_offset)
        if control & self._CR_ADCAL:
            self._calibration_reads_remaining = 8

        if self._isr_offset is not None and (control & self._CR_ADEN):
            isr = self.read_register_value(self._isr_offset)
            self.write_register_value(self._isr_offset, isr | self._ISR_ADRDY)

    def read(self, offset: int, size: int) -> int:
        if (
            size == 4
            and self._cr_offset is not None
            and offset == self._cr_offset
            and self._calibration_reads_remaining > 0
        ):
            self._calibration_reads_remaining -= 1
            if self._calibration_reads_remaining == 0:
                control = self.read_register_value(self._cr_offset)
                self.write_register_value(self._cr_offset, control & ~self._CR_ADCAL)
        return super().read(offset, size)

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["calibration_reads_remaining"] = int(self._calibration_reads_remaining)
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        self._calibration_reads_remaining = int(state.get("calibration_reads_remaining", 0))


def build_adc(peripheral: SvdPeripheral) -> Stm32AdcPeripheral:
    return Stm32AdcPeripheral(peripheral=peripheral)
