"""ADC peripheral with conversion simulation, DMA, and event support."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext, PeripheralEvent
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class Stm32AdcPeripheral(GenericRegisterFilePeripheral):
    """ADC with conversion start/complete, EOC/EOS flags, DMA, and IRQ.

    Conversion model:
      Writing ADSTART triggers an instant conversion. The result is
      taken from the sample queue (``inject_sample()``) or defaults
      to ``default_sample``. EOC/EOS flags are set, an ``adc_eoc``
      event is emitted, and if DMA mode is enabled a ``dma_request``
      is issued for the DR register address.
    """

    irq: int | None = None
    default_sample: int = 2048
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _sample_queue: deque[int] = field(default_factory=deque, init=False, repr=False)
    _calibration_reads_remaining: int = field(default=0, init=False, repr=False)
    _conversion_count: int = field(default=0, init=False, repr=False)
    _trigger_source: str = field(default="", init=False, repr=False)

    _CR = 0x08
    _ISR = 0x00
    _IER = 0x04
    _DR = 0x40
    _CFGR = 0x0C

    _CR_ADEN = 1 << 0
    _CR_ADDIS = 1 << 1
    _CR_ADSTART = 1 << 2
    _CR_ADCAL = 1 << 31

    _ISR_ADRDY = 1 << 0
    _ISR_EOC = 1 << 2
    _ISR_EOS = 1 << 3
    _ISR_OVR = 1 << 4

    _IER_ADRDYIE = 1 << 0
    _IER_EOCIE = 1 << 2
    _IER_EOSIE = 1 << 3

    _CFGR_DMAEN = 1 << 0
    _CFGR_CONT = 1 << 13

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "CR":
                self._CR = reg.offset
            elif rname in ("ISR", "SR"):
                self._ISR = reg.offset
            elif rname in ("IER",):
                self._IER = reg.offset
            elif rname in ("DR",):
                self._DR = reg.offset
            elif rname in ("CFGR", "CFGR1"):
                self._CFGR = reg.offset

    def attach(self, context: PeripheralContext) -> None:
        self._context = context
        if context.bus is not None:
            context.bus.subscribe("timer_update", self._on_timer_update)

    def reset(self) -> None:
        super().reset()
        self._sample_queue.clear()
        self._calibration_reads_remaining = 0
        self._conversion_count = 0
        self._trigger_source = ""

    def write(self, offset: int, size: int, value: int) -> None:
        if self._access_targets(offset, size, self._ISR):
            clear_mask = self._aligned_write_value(offset, size, self._ISR, value)
            isr = self.read_register_value(self._ISR)
            self.write_register_value(self._ISR, isr & ~clear_mask)
            return

        super().write(offset, size, value)

        if self._access_targets(offset, size, self._CR):
            self._handle_cr_write()

    def read(self, offset: int, size: int) -> int:
        if self._access_targets(offset, size, self._CR) and self._calibration_reads_remaining > 0:
            self._calibration_reads_remaining -= 1
            if self._calibration_reads_remaining == 0:
                cr = self.read_register_value(self._CR)
                self.write_register_value(self._CR, cr & ~self._CR_ADCAL)
        if self._access_targets(offset, size, self._DR):
            isr = self.read_register_value(self._ISR)
            self.write_register_value(self._ISR, isr & ~(self._ISR_EOC | self._ISR_EOS))
        return super().read(offset, size)

    def _handle_cr_write(self) -> None:
        cr = self.read_register_value(self._CR)

        if cr & self._CR_ADCAL:
            self._calibration_reads_remaining = 8

        if cr & self._CR_ADEN:
            isr = self.read_register_value(self._ISR)
            self.write_register_value(self._ISR, isr | self._ISR_ADRDY)
            self._update_irq()

        if cr & self._CR_ADSTART:
            self.write_register_value(self._CR, cr & ~self._CR_ADSTART)
            self._do_conversion()

    def _do_conversion(self) -> None:
        if self._sample_queue:
            sample = self._sample_queue.popleft()
        else:
            sample = self.default_sample
        self._conversion_count += 1

        self.write_register_value(self._DR, sample & 0xFFFF)

        isr = self.read_register_value(self._ISR)
        isr |= self._ISR_EOC | self._ISR_EOS
        self.write_register_value(self._ISR, isr)

        self._emit_eoc_event(sample)
        self._emit_dma_request()
        self._update_irq()

    def _emit_eoc_event(self, sample: int) -> None:
        if self._context is None or self._context.bus is None:
            return
        self._context.bus.emit(PeripheralEvent(
            kind="adc_eoc",
            source=self._context.name,
            address=self._context.base + self._DR,
            payload={"sample": sample, "conversion": self._conversion_count},
        ))

    def _emit_dma_request(self) -> None:
        if self._context is None or self._context.bus is None:
            return
        cfgr = self.read_register_value(self._CFGR)
        if cfgr & self._CFGR_DMAEN:
            self._context.bus.request_dma(
                self._context.base + self._DR, "p2m", size=2,
                source=self._context.name,
            )

    def _update_irq(self) -> None:
        if self.irq is None or self._context is None or self._context.interrupts is None:
            return
        ier = self.read_register_value(self._IER)
        isr = self.read_register_value(self._ISR)
        pending = bool(
            ((ier & self._IER_EOCIE) and (isr & self._ISR_EOC))
            or ((ier & self._IER_EOSIE) and (isr & self._ISR_EOS))
            or ((ier & self._IER_ADRDYIE) and (isr & self._ISR_ADRDY))
        )
        self._context.interrupts.set_irq_pending(self.irq, pending)

    def set_external_trigger(self, source: str) -> None:
        """Configure a timer (by name) as the external trigger source."""
        self._trigger_source = source.upper()

    def clear_external_trigger(self) -> None:
        self._trigger_source = ""

    def _on_timer_update(self, event: PeripheralEvent) -> None:
        if not self._trigger_source:
            return
        if event.source.upper() != self._trigger_source:
            return
        cr = self.read_register_value(self._CR)
        if not (cr & self._CR_ADEN):
            return
        self._do_conversion()

    def inject_sample(self, value: int) -> None:
        """Queue a sample value for the next conversion."""
        self._sample_queue.append(int(value) & 0xFFFF)

    def inject_samples(self, values: list[int]) -> None:
        """Queue multiple sample values."""
        for v in values:
            self._sample_queue.append(int(v) & 0xFFFF)

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["calibration_reads_remaining"] = self._calibration_reads_remaining
        base["sample_queue"] = list(self._sample_queue)
        base["conversion_count"] = self._conversion_count
        base["default_sample"] = self.default_sample
        base["trigger_source"] = self._trigger_source
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        self._calibration_reads_remaining = int(state.get("calibration_reads_remaining", 0))
        sq = state.get("sample_queue")
        if isinstance(sq, list):
            self._sample_queue = deque(int(v) & 0xFFFF for v in sq)
        self._conversion_count = int(state.get("conversion_count", 0))
        self.default_sample = int(state.get("default_sample", self.default_sample))
        self._trigger_source = str(state.get("trigger_source", ""))


def _first_irq(peripheral: SvdPeripheral) -> int | None:
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


def build_adc(peripheral: SvdPeripheral) -> Stm32AdcPeripheral:
    return Stm32AdcPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
