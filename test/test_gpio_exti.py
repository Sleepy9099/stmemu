"""Tests for GPIO input injection, edge events, and EXTI interrupt path."""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.gpio import GpioPeripheral, MODE_INPUT, MODE_OUTPUT
from stmemu.peripherals.exti import ExtiPeripheral


_GPIO_REGS = (
    SvdRegister(name="MODER", offset=0x00),
    SvdRegister(name="OTYPER", offset=0x04),
    SvdRegister(name="OSPEEDR", offset=0x08),
    SvdRegister(name="PUPDR", offset=0x0C),
    SvdRegister(name="IDR", offset=0x10, access="ro"),
    SvdRegister(name="ODR", offset=0x14),
    SvdRegister(name="BSRR", offset=0x18, access="wo"),
    SvdRegister(name="LCKR", offset=0x1C),
    SvdRegister(name="AFRL", offset=0x20),
    SvdRegister(name="AFRH", offset=0x24),
)


def _make_svd(name, base, registers=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=base, size=0x400,
        registers=registers, interrupts=interrupts,
    )


def _make_gpio():
    return GpioPeripheral(_make_svd("GPIOA", 0x40020000, _GPIO_REGS))


class _FakeNvic:
    def __init__(self):
        self.pending: dict[int, bool] = {}

    def set_irq_pending(self, irq, pending=True):
        self.pending[irq] = pending

    def set_system_pending(self, name, pending=True):
        pass


def _make_bus_gpio_exti():
    gpio_svd = _make_svd("GPIOA", 0x40020000, _GPIO_REGS)
    exti_svd = _make_svd("EXTI", 0x40013C00, interrupts=(
        SvdInterrupt(name="EXTI0", value=6),
        SvdInterrupt(name="EXTI1", value=7),
        SvdInterrupt(name="EXTI2", value=8),
        SvdInterrupt(name="EXTI3", value=9),
        SvdInterrupt(name="EXTI4", value=10),
        SvdInterrupt(name="EXTI9_5", value=23),
        SvdInterrupt(name="EXTI15_10", value=40),
    ))
    ranges = (
        AddressRange(base=0x40020000, end=0x40020400, peripheral=gpio_svd),
        AddressRange(base=0x40013C00, end=0x40014000, peripheral=exti_svd),
    )
    amap = AddressMap(device_name="TEST", peripherals=(gpio_svd, exti_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic

    gpio = GpioPeripheral(gpio_svd)
    bus.register_peripheral("GPIOA", gpio)

    exti = ExtiPeripheral(irq_map={0: 6, 1: 7, 2: 8, 3: 9, 4: 10, 5: 23, 10: 40})
    bus.mount(name="EXTI", base=0x40013C00, size=0x400, model=exti)

    return bus, gpio, exti, nvic


# ── GPIO input injection tests ───────────────────────────────────


class GpioInputTests(unittest.TestCase):
    def test_set_input_level_high(self):
        gpio = _make_gpio()
        gpio.set_input_level(3, True)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 3))

    def test_set_input_level_low(self):
        gpio = _make_gpio()
        gpio.set_input_level(3, True)
        gpio.set_input_level(3, False)
        idr = gpio.read(0x10, 4)
        self.assertFalse(idr & (1 << 3))

    def test_input_level_does_not_affect_output_pin(self):
        gpio = _make_gpio()
        gpio.write(0x00, 4, 0x01 << (2 * 5))  # Pin 5 = output
        gpio.write(0x18, 4, 1 << 5)  # Set ODR pin 5
        gpio.set_input_level(5, False)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 5), "output pin should reflect ODR, not input level")

    def test_set_input_mask(self):
        gpio = _make_gpio()
        gpio.set_input_mask(0x000F, 0x000A)  # Pins 1,3 high; 0,2 low
        idr = gpio.read(0x10, 4)
        self.assertFalse(idr & (1 << 0))
        self.assertTrue(idr & (1 << 1))
        self.assertFalse(idr & (1 << 2))
        self.assertTrue(idr & (1 << 3))

    def test_set_input_same_value_no_event(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        bus.event_log_enabled = True
        gpio.set_input_level(0, True)
        bus.drain_event_log()
        gpio.set_input_level(0, True)  # same value
        log = bus.drain_event_log()
        self.assertEqual(len(log), 0)

    def test_idr_mixed_input_output(self):
        gpio = _make_gpio()
        gpio.write(0x00, 4, 0x01)  # Pin 0 = output
        gpio.write(0x18, 4, 1 << 0)  # Set ODR pin 0
        gpio.set_input_level(1, True)  # Pin 1 = input high
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 0))  # output pin
        self.assertTrue(idr & (1 << 1))  # input pin

    def test_snapshot_restore_input_levels(self):
        gpio = _make_gpio()
        gpio.set_input_level(7, True)
        state = gpio.snapshot_state()
        gpio.reset()
        self.assertFalse(gpio.read(0x10, 4) & (1 << 7))
        gpio.restore_state(state)
        self.assertTrue(gpio.read(0x10, 4) & (1 << 7))

    def test_reset_clears_input_levels(self):
        gpio = _make_gpio()
        gpio.set_input_level(0, True)
        gpio.reset()
        self.assertEqual(gpio.read(0x10, 4), 0)


# ── GPIO edge event tests ────────────────────────────────────────


class GpioEdgeEventTests(unittest.TestCase):
    def test_rising_edge_emits_event(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        bus.event_log_enabled = True
        gpio.set_input_level(0, True)
        log = bus.drain_event_log()
        edges = [e for e in log if e.kind == "gpio_edge"]
        self.assertEqual(len(edges), 1)
        self.assertTrue(edges[0].payload["rising"])
        self.assertFalse(edges[0].payload["falling"])
        self.assertEqual(edges[0].source, "GPIOA")

    def test_falling_edge_emits_event(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        gpio.set_input_level(0, True)
        bus.event_log_enabled = True
        gpio.set_input_level(0, False)
        log = bus.drain_event_log()
        edges = [e for e in log if e.kind == "gpio_edge"]
        self.assertEqual(len(edges), 1)
        self.assertTrue(edges[0].payload["falling"])

    def test_mask_emits_multiple_edges(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        bus.event_log_enabled = True
        gpio.set_input_mask(0x0005, 0x0005)  # Pins 0,2 high
        log = bus.drain_event_log()
        edges = [e for e in log if e.kind == "gpio_edge"]
        self.assertEqual(len(edges), 2)
        pins = {e.payload["pin"] for e in edges}
        self.assertEqual(pins, {0, 2})


# ── EXTI tests ────────────────────────────────────────────────────


class ExtiTests(unittest.TestCase):
    def test_rising_edge_sets_pr(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 0)  # Rising edge on line 0
        exti.write_register_value(exti._IMR, 1 << 0)   # Unmask line 0
        gpio.set_input_level(0, True)
        pr = exti.read_register_value(exti._PR)
        self.assertTrue(pr & 1, "EXTI PR should be set on rising edge")

    def test_falling_edge_sets_pr(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._FTSR, 1 << 0)
        exti.write_register_value(exti._IMR, 1 << 0)
        gpio.set_input_level(0, True)
        gpio.set_input_level(0, False)
        pr = exti.read_register_value(exti._PR)
        self.assertTrue(pr & 1)

    def test_masked_line_no_irq(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 0)
        # IMR bit 0 NOT set
        gpio.set_input_level(0, True)
        self.assertFalse(nvic.pending.get(6, False))

    def test_unmasked_line_pends_irq(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 0)
        exti.write_register_value(exti._IMR, 1 << 0)
        gpio.set_input_level(0, True)
        self.assertTrue(nvic.pending.get(6, False))

    def test_pr_write_1_clears(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 0)
        exti.write_register_value(exti._IMR, 1 << 0)
        gpio.set_input_level(0, True)
        self.assertTrue(exti.read_register_value(exti._PR) & 1)
        exti.write(exti._PR, 4, 1 << 0)  # Write-1-to-clear
        self.assertFalse(exti.read_register_value(exti._PR) & 1)

    def test_no_trigger_without_rtsr_ftsr(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._IMR, 1 << 0)
        # Neither RTSR nor FTSR set
        gpio.set_input_level(0, True)
        pr = exti.read_register_value(exti._PR)
        self.assertFalse(pr & 1)

    def test_exti9_5_group_irq(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 7)  # Line 7
        exti.write_register_value(exti._IMR, 1 << 7)
        gpio.set_input_level(7, True)
        self.assertTrue(nvic.pending.get(23, False), "EXTI9_5 IRQ should pend")

    def test_exti15_10_group_irq(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 1 << 12)
        exti.write_register_value(exti._IMR, 1 << 12)
        gpio.set_input_level(12, True)
        self.assertTrue(nvic.pending.get(40, False), "EXTI15_10 IRQ should pend")

    def test_swier_sets_pr_and_irq(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._IMR, 1 << 3)
        exti.write(exti._SWIER, 4, 1 << 3)
        pr = exti.read_register_value(exti._PR)
        self.assertTrue(pr & (1 << 3))
        self.assertTrue(nvic.pending.get(9, False))

    def test_snapshot_restore_exti(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, 0x000F)
        exti.write_register_value(exti._IMR, 0x000F)
        gpio.set_input_level(0, True)
        state = exti.snapshot_state()
        exti.reset()
        self.assertEqual(exti.read_register_value(exti._PR), 0)
        exti.restore_state(state)
        self.assertTrue(exti.read_register_value(exti._PR) & 1)

    def test_multiple_lines_independent(self):
        bus, gpio, exti, nvic = _make_bus_gpio_exti()
        exti.write_register_value(exti._RTSR, (1 << 0) | (1 << 4))
        exti.write_register_value(exti._IMR, (1 << 0) | (1 << 4))
        gpio.set_input_level(0, True)
        self.assertTrue(nvic.pending.get(6, False))
        self.assertFalse(nvic.pending.get(10, False))
        gpio.set_input_level(4, True)
        self.assertTrue(nvic.pending.get(10, False))


if __name__ == "__main__":
    unittest.main()
