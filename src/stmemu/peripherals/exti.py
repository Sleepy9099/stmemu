"""EXTI (External Interrupt/Event Controller) peripheral model.

Subscribes to ``gpio_edge`` events on the bus and sets pending bits
based on rising/falling edge configuration. Maps EXTI lines to NVIC
IRQs using the standard STM32 grouping:

  EXTI0..4    → individual IRQs
  EXTI5..9    → shared EXTI9_5
  EXTI10..15  → shared EXTI15_10
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext, PeripheralEvent
from stmemu.peripherals.registers import RegisterPeripheral, RegisterSpec
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

# Default EXTI IRQ numbers (STM32F4-style, overridable via constructor)
_DEFAULT_EXTI_IRQS: dict[int, int] = {
    0: 6,
    1: 7,
    2: 8,
    3: 9,
    4: 10,
    5: 23,   # EXTI9_5
    10: 40,  # EXTI15_10
}


@dataclass
class ExtiPeripheral(RegisterPeripheral):
    """EXTI controller with event-driven edge detection."""

    _IMR = 0x00
    _EMR = 0x04
    _RTSR = 0x08
    _FTSR = 0x0C
    _SWIER = 0x10
    _PR = 0x14

    irq_map: dict[int, int] = field(default_factory=lambda: dict(_DEFAULT_EXTI_IRQS))
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)

    def __init__(self, *, irq_map: dict[int, int] | None = None):
        super().__init__("EXTI")
        if irq_map is not None:
            self.irq_map = dict(irq_map)
        else:
            self.irq_map = dict(_DEFAULT_EXTI_IRQS)
        self._context = None
        self.add_register(RegisterSpec(name="IMR", offset=self._IMR))
        self.add_register(RegisterSpec(name="EMR", offset=self._EMR))
        self.add_register(RegisterSpec(name="RTSR", offset=self._RTSR))
        self.add_register(RegisterSpec(name="FTSR", offset=self._FTSR))
        self.add_register(RegisterSpec(
            name="SWIER", offset=self._SWIER,
            on_write=self._on_write_swier,
        ))
        self.add_register(RegisterSpec(
            name="PR", offset=self._PR,
            on_write=self._on_write_pr,
        ))

    def attach(self, context: PeripheralContext) -> None:
        self._context = context
        if context.bus is not None:
            context.bus.subscribe("gpio_edge", self._on_gpio_edge)

    def _on_gpio_edge(self, event: PeripheralEvent) -> None:
        payload = event.payload
        if not isinstance(payload, dict):
            return
        pin = int(payload.get("pin", -1))
        if pin < 0 or pin > 15:
            return
        rising = bool(payload.get("rising", False))
        falling = bool(payload.get("falling", False))
        mask = 1 << pin
        rtsr = self.read_register_value(self._RTSR)
        ftsr = self.read_register_value(self._FTSR)
        triggered = False
        if rising and (rtsr & mask):
            triggered = True
        if falling and (ftsr & mask):
            triggered = True
        if triggered:
            pr = self.read_register_value(self._PR)
            self.write_register_value(self._PR, pr | mask)
            self._pend_irq_for_line(pin)

    def _on_write_swier(self, current: int, next_value: int) -> int:
        new_bits = next_value & ~current
        if new_bits:
            pr = self.read_register_value(self._PR)
            self.write_register_value(self._PR, pr | new_bits)
            for pin in range(16):
                if new_bits & (1 << pin):
                    self._pend_irq_for_line(pin)
        return current | next_value

    def _on_write_pr(self, current: int, next_value: int) -> int:
        # Write-1-to-clear
        return current & ~next_value

    def _pend_irq_for_line(self, line: int) -> None:
        imr = self.read_register_value(self._IMR)
        if not (imr & (1 << line)):
            return
        if self._context is None or self._context.interrupts is None:
            return
        irq = self._irq_for_line(line)
        if irq is not None:
            self._context.interrupts.set_irq_pending(irq)

    def _irq_for_line(self, line: int) -> int | None:
        if line in self.irq_map:
            return self.irq_map[line]
        if 5 <= line <= 9:
            return self.irq_map.get(5)
        if 10 <= line <= 15:
            return self.irq_map.get(10)
        return None

    def snapshot_state(self) -> object | None:
        return {
            "values": {int(k): int(v) for k, v in self._values.items()},
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict):
            return
        vals = state.get("values")
        if isinstance(vals, dict):
            for k, v in vals.items():
                self._values[int(k)] = int(v)
