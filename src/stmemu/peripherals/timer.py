from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext, PeripheralEvent
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class BasicTimerPeripheral(GenericRegisterFilePeripheral):
    irq: int | None = None
    # Coalesce a multi-period advance into one update event (default) instead
    # of emitting one event per overflow ("exact" mode).
    coalesce_updates: bool = True
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _prescaler_accum: int = field(default=0, init=False, repr=False)
    _last_counter: int = field(default=0, init=False, repr=False)
    _update_count: int = field(default=0, init=False, repr=False)

    _CR1 = 0x00
    _DIER = 0x0C
    _SR = 0x10
    _EGR = 0x14
    _CNT = 0x24
    _PSC = 0x28
    _ARR = 0x2C
    _CCR1 = 0x34

    _CR1_CEN = 1 << 0
    _CR1_OPM = 1 << 3
    _DIER_UIE = 1 << 0
    _DIER_CC1IE = 1 << 1
    _SR_UIF = 1 << 0
    _SR_CC1IF = 1 << 1
    _EGR_UG = 1 << 0

    def reset(self) -> None:
        super().reset()
        self._prescaler_accum = 0
        self._last_counter = 0
        self._update_count = 0
        self._update_irq()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def tick(self, cycles: int) -> None:
        cr1 = self.read_register_value(self._CR1)
        if not (cr1 & self._CR1_CEN):
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
        total = old_counter + steps

        # How many times the counter rolled over ARR during this advance. A
        # large accelerated jump (idle fast-forward) can cross many periods at
        # once; we must not silently lose them.
        overflows = total // period
        one_pulse = bool(overflows > 0 and (cr1 & self._CR1_OPM))
        # One-pulse mode generates a single update then stops, regardless of how
        # many periods the jump spanned.
        new_counter = 0 if one_pulse else total % period

        # Settle the counter *before* emitting the update event so its payload
        # reports the final (wrapped) CNT, not the pre-overflow value.
        self.write_register_value(self._CNT, new_counter)
        self._last_counter = new_counter

        if overflows > 0:
            if one_pulse:
                self.write_register_value(self._CR1, cr1 & ~self._CR1_CEN)
                self._on_update_event(1)
            elif self.coalesce_updates:
                # Coalesce into one event carrying the overflow count, so an
                # accelerated idle jump doesn't flood the event trace.
                self._on_update_event(overflows)
            else:
                for _ in range(overflows):
                    self._on_update_event(1)

        compare = self.read_register_value(self._CCR1) & 0xFFFFFFFF
        if self._crossed_compare(old_counter, total, compare, period):
            self.write_register_value(self._SR, self.read_register_value(self._SR) | self._SR_CC1IF)

        self._update_irq()

    def write(self, offset: int, size: int, value: int) -> None:
        if self._access_targets(offset, size, self._SR):
            # SR is rc_w0: writing 0 clears a flag, writing 1 keeps it. For a
            # sub-word write only the written bytes participate; bytes outside
            # the access keep their current value.
            current = self.read_register_value(self._SR)
            aligned = self._aligned_write_value(offset, size, self._SR, value)
            keep_outside = ~self._written_byte_mask(offset, size, self._SR)
            self.write_register_value(self._SR, current & (aligned | keep_outside))
            self._update_irq()
            return

        if self._access_targets(offset, size, self._EGR):
            super().write(offset, size, value)
            if self._aligned_write_value(offset, size, self._EGR, value) & self._EGR_UG:
                self.write_register_value(self._CNT, 0)
                self._prescaler_accum = 0
                self._on_update_event()
            self._update_irq()
            return

        super().write(offset, size, value)
        if offset in {self._CR1, self._DIER, self._CCR1}:
            self._catch_up_compare()
            self._update_irq()

    def cycles_until_irq(self) -> int | None:
        """Cycles until this timer next raises an enabled interrupt.

        Used by the emulator's idle fast-forward: when the CPU is parked in
        the idle self-loop, time can jump straight to the next timer event
        instead of single-stepping millions of idle instructions. Returns
        None when the timer is stopped or has no enabled IRQ source.
        """
        cr1 = self.read_register_value(self._CR1)
        if not (cr1 & self._CR1_CEN):
            return None
        dier = self.read_register_value(self._DIER)
        if not (dier & (self._DIER_UIE | self._DIER_CC1IE)):
            return None
        divider = max(1, (self.read_register_value(self._PSC) & 0xFFFF) + 1)
        cnt = self.read_register_value(self._CNT) & 0xFFFFFFFF
        arr = self.read_register_value(self._ARR) & 0xFFFFFFFF
        period = arr + 1 if arr < 0xFFFFFFFF else 0x100000000
        if period <= 0:
            return None
        candidates: list[int] = []
        if dier & self._DIER_UIE:
            candidates.append(period - cnt)
        if dier & self._DIER_CC1IE:
            ccr1 = self.read_register_value(self._CCR1) & 0xFFFFFFFF
            d = (ccr1 - cnt) % period
            candidates.append(d if d != 0 else period)
        if not candidates:
            return None
        ticks = max(0, min(candidates))
        # Subtract the prescaler cycles already accumulated toward the next tick.
        cycles = ticks * divider - self._prescaler_accum
        return max(1, int(cycles))

    def _on_update_event(self, overflows: int = 1) -> None:
        self._update_count += max(1, int(overflows))
        sr = self.read_register_value(self._SR)
        self.write_register_value(self._SR, sr | self._SR_UIF)
        self._emit_update_event(overflows)
        self._update_irq()

    def _emit_update_event(self, overflows: int = 1) -> None:
        if self._context is None or self._context.bus is None:
            return
        self._context.bus.emit(PeripheralEvent(
            kind="timer_update",
            source=self._context.name,
            payload={
                "overflows": max(1, int(overflows)),
                "cnt": self.read_register_value(self._CNT),
                "arr": self.read_register_value(self._ARR),
                "psc": self.read_register_value(self._PSC),
                "update_count": self._update_count,
            },
        ))

    def _update_irq(self) -> None:
        if self.irq is None or self._context is None or self._context.interrupts is None:
            return
        sr = self.read_register_value(self._SR)
        dier = self.read_register_value(self._DIER)
        pending = bool(
            ((sr & self._SR_UIF) and (dier & self._DIER_UIE))
            or ((sr & self._SR_CC1IF) and (dier & self._DIER_CC1IE))
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

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["prescaler_accum"] = int(self._prescaler_accum)
        base["last_counter"] = int(self._last_counter) & 0xFFFFFFFF
        base["update_count"] = int(self._update_count)
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        self._prescaler_accum = int(state.get("prescaler_accum", 0))
        self._last_counter = int(state.get("last_counter", 0)) & 0xFFFFFFFF
        self._update_count = int(state.get("update_count", 0))
        self._update_irq()


def _first_irq(peripheral: SvdPeripheral) -> Optional[int]:
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


def build_timer(peripheral: SvdPeripheral) -> BasicTimerPeripheral:
    return BasicTimerPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
