from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class BasicTimerPeripheral(GenericRegisterFilePeripheral):
    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _prescaler_accum: int = field(default=0, init=False, repr=False)
    _last_counter: int = field(default=0, init=False, repr=False)

    _CR1 = 0x00
    _DIER = 0x0C
    _SR = 0x10
    _EGR = 0x14
    _CNT = 0x24
    _PSC = 0x28
    _ARR = 0x2C
    _CCR1 = 0x34

    _CR1_CEN = 1 << 0
    _DIER_CC1IE = 1 << 1
    _SR_CC1IF = 1 << 1
    _EGR_UG = 1 << 0

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def tick(self, cycles: int) -> None:
        if not (self.read_register_value(self._CR1) & self._CR1_CEN):
            return

        prescaler = self.read_register_value(self._PSC) & 0xFFFF
        divider = max(1, prescaler + 1)
        self._prescaler_accum += max(0, int(cycles))
        steps = self._prescaler_accum // divider
        self._prescaler_accum %= divider
        if steps <= 0:
            return

        arr = self.read_register_value(self._ARR) & 0xFFFFFFFF
        period = arr + 1 if arr < 0xFFFFFFFF else 0x100000000
        old_counter = self.read_register_value(self._CNT) & 0xFFFFFFFF
        new_counter = (old_counter + steps) % period
        self.write_register_value(self._CNT, new_counter)
        self._last_counter = new_counter

        compare = self.read_register_value(self._CCR1) & 0xFFFFFFFF
        if self._crossed_compare(old_counter, new_counter, compare, period):
            self.write_register_value(self._SR, self.read_register_value(self._SR) | self._SR_CC1IF)

        self._update_irq()

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._SR:
            # TIM status bits clear when software writes 0 to the corresponding bit.
            current = self.read_register_value(self._SR)
            self.write_register_value(self._SR, current & int(value))
            self._update_irq()
            return

        if size == 4 and offset == self._EGR:
            super().write(offset, size, value)
            if int(value) & self._EGR_UG:
                self.write_register_value(self._CNT, 0)
                self._prescaler_accum = 0
            self._update_irq()
            return

        super().write(offset, size, value)
        if offset in {self._CR1, self._DIER, self._CCR1}:
            self._catch_up_compare()
            self._update_irq()

    def _update_irq(self) -> None:
        if self.irq is None or self._context is None or self._context.interrupts is None:
            return
        pending = bool(
            (self.read_register_value(self._SR) & self._SR_CC1IF)
            and (self.read_register_value(self._DIER) & self._DIER_CC1IE)
        )
        self._context.interrupts.set_irq_pending(self.irq, pending)

    @staticmethod
    def _crossed_compare(old_counter: int, new_counter: int, compare: int, period: int) -> bool:
        if period <= 0:
            return False
        compare %= period
        old_counter %= period
        new_counter %= period
        if old_counter == new_counter:
            return False
        if old_counter < new_counter:
            return old_counter < compare <= new_counter
        return compare > old_counter or compare <= new_counter

    def _catch_up_compare(self) -> None:
        if not (self.read_register_value(self._CR1) & self._CR1_CEN):
            return
        if not (self.read_register_value(self._DIER) & self._DIER_CC1IE):
            return

        counter = self.read_register_value(self._CNT) & 0xFFFFFFFF
        compare = self.read_register_value(self._CCR1) & 0xFFFFFFFF
        if ((counter - compare) & 0xFFFFFFFF) < 0x80000000:
            self.write_register_value(self._SR, self.read_register_value(self._SR) | self._SR_CC1IF)


def build_tim5(peripheral: SvdPeripheral) -> BasicTimerPeripheral:
    return BasicTimerPeripheral(peripheral=peripheral, irq=50)
