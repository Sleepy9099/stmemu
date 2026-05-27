"""Tests for timer-triggered ADC conversion chain."""
from __future__ import annotations

import struct
import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.adc import Stm32AdcPeripheral
from stmemu.peripherals.timer import BasicTimerPeripheral
from stmemu.peripherals.dma import DmaPeripheral


_ADC_REGS = (
    SvdRegister(name="ISR", offset=0x00),
    SvdRegister(name="IER", offset=0x04),
    SvdRegister(name="CR", offset=0x08),
    SvdRegister(name="CFGR", offset=0x0C),
    SvdRegister(name="DR", offset=0x40),
)

_TIMER_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="DIER", offset=0x0C),
    SvdRegister(name="SR", offset=0x10),
    SvdRegister(name="EGR", offset=0x14),
    SvdRegister(name="CNT", offset=0x24),
    SvdRegister(name="PSC", offset=0x28),
    SvdRegister(name="ARR", offset=0x2C),
    SvdRegister(name="CCR1", offset=0x34),
)

_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
)


def _make_svd(name, base, registers=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=base, size=0x400,
        registers=registers, interrupts=interrupts,
    )


class _FakeNvic:
    def __init__(self):
        self.pending: dict[int, bool] = {}
    def set_irq_pending(self, irq, pending=True):
        self.pending[irq] = pending
    def set_system_pending(self, name, pending=True):
        pass


def _make_bus_timer_adc():
    tim_svd = _make_svd("TIM2", 0x40000000, _TIMER_REGS,
        interrupts=(SvdInterrupt(name="TIM2", value=28),))
    adc_svd = _make_svd("ADC1", 0x40012000, _ADC_REGS,
        interrupts=(SvdInterrupt(name="ADC1_2", value=18),))
    ranges = (
        AddressRange(base=0x40000000, end=0x40000400, peripheral=tim_svd),
        AddressRange(base=0x40012000, end=0x40012400, peripheral=adc_svd),
    )
    amap = AddressMap(device_name="TEST", peripherals=(tim_svd, adc_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic

    tim = BasicTimerPeripheral(peripheral=tim_svd, irq=28)
    adc = Stm32AdcPeripheral(peripheral=adc_svd, irq=18)
    bus.register_peripheral("TIM2", tim)
    bus.register_peripheral("ADC1", adc)
    return bus, tim, adc, nvic


# ── Timer-triggered ADC conversion ───────────────────────────────


class TimerTriggeredAdcTests(unittest.TestCase):
    def test_timer_overflow_triggers_adc_conversion(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_sample(3000)

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        dr = adc.read_register_value(adc._DR)
        self.assertEqual(dr, 3000)
        isr = adc.read_register_value(adc._ISR)
        self.assertTrue(isr & adc._ISR_EOC)

    def test_no_trigger_without_set_external_trigger(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.inject_sample(3000)

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        self.assertEqual(adc._conversion_count, 0)

    def test_trigger_ignored_when_adc_disabled(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.set_external_trigger("TIM2")
        adc.inject_sample(3000)

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        self.assertEqual(adc._conversion_count, 0)

    def test_wrong_timer_does_not_trigger(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM3")
        adc.inject_sample(3000)

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        self.assertEqual(adc._conversion_count, 0)

    def test_clear_trigger_stops_conversions(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_samples([100, 200])

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertEqual(adc._conversion_count, 1)

        adc.clear_external_trigger()
        tim.tick(10)
        self.assertEqual(adc._conversion_count, 1)

    def test_multiple_overflows_multiple_conversions(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_samples([100, 200, 300])

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)

        tim.tick(10)
        self.assertEqual(adc._conversion_count, 1)
        self.assertEqual(adc.read_register_value(adc._DR), 100)

        tim.tick(10)
        self.assertEqual(adc._conversion_count, 2)
        self.assertEqual(adc.read_register_value(adc._DR), 200)


# ── Full chain: timer → ADC → event/DMA/IRQ ─────────────────────


class FullChainTests(unittest.TestCase):
    def test_timer_adc_eoc_event(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        bus.event_log_enabled = True
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_sample(2048)

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        log = bus.drain_event_log()
        timer_events = [e for e in log if e.kind == "timer_update"]
        adc_events = [e for e in log if e.kind == "adc_eoc"]
        self.assertEqual(len(timer_events), 1)
        self.assertEqual(len(adc_events), 1)
        self.assertEqual(adc_events[0].payload["sample"], 2048)

    def test_timer_adc_irq(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.write(adc._IER, 4, adc._IER_EOCIE)
        adc.set_external_trigger("TIM2")

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        self.assertTrue(nvic.pending.get(18, False), "ADC IRQ should pend")

    def test_timer_adc_dma_request(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        bus.event_log_enabled = True
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.write(adc._CFGR, 4, adc._CFGR_DMAEN)
        adc.set_external_trigger("TIM2")

        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)

        log = bus.drain_event_log()
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertGreater(len(dma_reqs), 0)
        self.assertEqual(dma_reqs[0].source, "ADC1")
        self.assertEqual(dma_reqs[0].direction, "p2m")

    def test_egr_ug_triggers_adc(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_sample(1111)

        tim.write(tim._EGR, 4, tim._EGR_UG)

        self.assertEqual(adc.read_register_value(adc._DR), 1111)

    def test_software_adstart_still_works(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        adc.set_external_trigger("TIM2")
        adc.inject_sample(999)

        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        self.assertEqual(adc.read_register_value(adc._DR), 999)


# ── Snapshot/restore ─────────────────────────────────────────────


class TriggerSnapshotTests(unittest.TestCase):
    def test_trigger_source_in_snapshot(self):
        bus, tim, adc, nvic = _make_bus_timer_adc()
        adc.set_external_trigger("TIM2")
        state = adc.snapshot_state()
        self.assertEqual(state["trigger_source"], "TIM2")
        adc.reset()
        self.assertEqual(adc._trigger_source, "")
        adc.restore_state(state)
        self.assertEqual(adc._trigger_source, "TIM2")


if __name__ == "__main__":
    unittest.main()
