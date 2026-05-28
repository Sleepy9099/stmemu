"""Tests for ADC conversion, DMA requests, events, and shell commands."""
from __future__ import annotations

import sys
import types
import unittest

# ── Stub external dependencies ─────────────────────────────────────

if "capstone" not in sys.modules:
    _cs = types.ModuleType("capstone")
    class _Cs:
        def __init__(self, *a, **k): self.detail = False
        def disasm(self, code, addr, count=0): return []
    _cs.Cs = _Cs
    _cs.CS_ARCH_ARM = 0
    _cs.CS_MODE_THUMB = 0
    sys.modules["capstone"] = _cs

if "unicorn" not in sys.modules:
    _uc = types.ModuleType("unicorn")
    _uc_const = types.ModuleType("unicorn.unicorn_const")
    _uc_const.UC_HOOK_CODE = 0
    _uc.unicorn_const = _uc_const
    sys.modules["unicorn"] = _uc
    sys.modules["unicorn.unicorn_const"] = _uc_const

if "stmemu.core.emulator" not in sys.modules:
    _emu = types.ModuleType("stmemu.core.emulator")
    class _PcRegWrite: pass
    class _Emulator: pass
    _emu.PcRegWrite = _PcRegWrite
    _emu.Emulator = _Emulator
    sys.modules["stmemu.core.emulator"] = _emu

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.adc import Stm32AdcPeripheral
from stmemu.peripherals.dma import DmaPeripheral


_ADC_REGS = (
    SvdRegister(name="ISR", offset=0x00),
    SvdRegister(name="IER", offset=0x04),
    SvdRegister(name="CR", offset=0x08),
    SvdRegister(name="CFGR", offset=0x0C),
    SvdRegister(name="DR", offset=0x40),
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


def _make_bus_adc():
    adc_svd = _make_svd("ADC1", 0x40012000, _ADC_REGS,
        interrupts=(SvdInterrupt(name="ADC1_2", value=18),))
    ranges = (AddressRange(base=0x40012000, end=0x40012400, peripheral=adc_svd),)
    amap = AddressMap(device_name="TEST", peripherals=(adc_svd,), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    adc = Stm32AdcPeripheral(peripheral=adc_svd, irq=18)
    bus.register_peripheral("ADC1", adc)
    return bus, adc, nvic


# ── Conversion tests ──────────────────────────────────────────────


class AdcConversionTests(unittest.TestCase):
    def test_adstart_triggers_conversion(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)  # Enable ADC
        adc.inject_sample(1234)
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        dr = adc.read(adc._DR, 4)
        self.assertEqual(dr, 1234)

    def test_eoc_flag_set_after_conversion(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        isr = adc.read_register_value(adc._ISR)
        self.assertTrue(isr & adc._ISR_EOC)
        self.assertTrue(isr & adc._ISR_EOS)

    def test_eoc_and_eos_cleared_on_dr_read(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        adc.read(adc._DR, 4)
        isr = adc.read_register_value(adc._ISR)
        self.assertFalse(isr & adc._ISR_EOC)
        self.assertFalse(isr & adc._ISR_EOS)

    def test_eoc_cleared_on_dr_halfword_read(self):
        # DR holds a 16-bit result; a halfword (LDRH) read must still clear EOC/EOS.
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        adc.read(adc._DR, 2)
        isr = adc.read_register_value(adc._ISR)
        self.assertFalse(isr & adc._ISR_EOC)
        self.assertFalse(isr & adc._ISR_EOS)

    def test_isr_write_1_clears(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        adc.write(adc._ISR, 4, adc._ISR_EOC | adc._ISR_EOS)
        isr = adc.read_register_value(adc._ISR)
        self.assertFalse(isr & adc._ISR_EOC)
        self.assertFalse(isr & adc._ISR_EOS)

    def test_default_sample_used_when_queue_empty(self):
        bus, adc, nvic = _make_bus_adc()
        adc.default_sample = 999
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        self.assertEqual(adc.read(adc._DR, 4), 999)

    def test_sample_queue_fifo(self):
        bus, adc, nvic = _make_bus_adc()
        adc.inject_samples([100, 200, 300])
        for expected in (100, 200, 300):
            adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
            self.assertEqual(adc.read(adc._DR, 4), expected)

    def test_adstart_clears_after_conversion(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        cr = adc.read_register_value(adc._CR)
        self.assertFalse(cr & adc._CR_ADSTART)

    def test_calibration_completes(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADCAL)
        for _ in range(8):
            adc.read(adc._CR, 4)
        cr = adc.read(adc._CR, 4)
        self.assertFalse(cr & adc._CR_ADCAL)

    def test_aden_sets_adrdy(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN)
        isr = adc.read_register_value(adc._ISR)
        self.assertTrue(isr & adc._ISR_ADRDY)


# ── Event tests ───────────────────────────────────────────────────


class AdcEventTests(unittest.TestCase):
    def test_eoc_event_emitted(self):
        bus, adc, nvic = _make_bus_adc()
        bus.event_log_enabled = True
        adc.inject_sample(4000)
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        log = bus.drain_event_log()
        eoc_events = [e for e in log if e.kind == "adc_eoc"]
        self.assertEqual(len(eoc_events), 1)
        self.assertEqual(eoc_events[0].source, "ADC1")
        self.assertEqual(eoc_events[0].payload["sample"], 4000)

    def test_eoc_event_address_is_dr(self):
        bus, adc, nvic = _make_bus_adc()
        bus.event_log_enabled = True
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        log = bus.drain_event_log()
        eoc = [e for e in log if e.kind == "adc_eoc"][0]
        self.assertEqual(eoc.address, 0x40012000 + 0x40)


# ── IRQ tests ─────────────────────────────────────────────────────


class AdcIrqTests(unittest.TestCase):
    def test_eocie_pends_irq(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._IER, 4, adc._IER_EOCIE)
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        self.assertTrue(nvic.pending.get(18, False))

    def test_no_irq_without_ier(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        self.assertFalse(nvic.pending.get(18, False))

    def test_adrdyie_pends_on_aden(self):
        bus, adc, nvic = _make_bus_adc()
        adc.write(adc._IER, 4, adc._IER_ADRDYIE)
        adc.write(adc._CR, 4, adc._CR_ADEN)
        self.assertTrue(nvic.pending.get(18, False))


# ── DMA tests ─────────────────────────────────────────────────────


class AdcDmaTests(unittest.TestCase):
    def test_dma_request_when_dmaen(self):
        bus, adc, nvic = _make_bus_adc()
        bus.event_log_enabled = True
        adc.write(adc._CFGR, 4, adc._CFGR_DMAEN)
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        log = bus.drain_event_log()
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertGreater(len(dma_reqs), 0)
        self.assertEqual(dma_reqs[0].source, "ADC1")
        self.assertEqual(dma_reqs[0].direction, "p2m")

    def test_no_dma_without_dmaen(self):
        bus, adc, nvic = _make_bus_adc()
        bus.event_log_enabled = True
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        log = bus.drain_event_log()
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertEqual(len(dma_reqs), 0)


# ── Snapshot tests ────────────────────────────────────────────────


class AdcSnapshotTests(unittest.TestCase):
    def test_snapshot_restore(self):
        bus, adc, nvic = _make_bus_adc()
        adc.inject_samples([100, 200])
        adc.default_sample = 555
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        state = adc.snapshot_state()
        adc.reset()
        self.assertEqual(len(adc._sample_queue), 0)
        adc.restore_state(state)
        self.assertEqual(adc.default_sample, 555)
        self.assertEqual(adc._conversion_count, 1)
        self.assertEqual(len(adc._sample_queue), 1)

    def test_reset_clears_state(self):
        bus, adc, nvic = _make_bus_adc()
        adc.inject_sample(42)
        adc.write(adc._CR, 4, adc._CR_ADEN | adc._CR_ADSTART)
        adc.reset()
        self.assertEqual(adc._conversion_count, 0)
        self.assertEqual(len(adc._sample_queue), 0)


# ── Shell command tests ───────────────────────────────────────────


class AdcShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        adc_svd = _make_svd("ADC1", 0x40012000, _ADC_REGS,
            interrupts=(SvdInterrupt(name="ADC1_2", value=18),))
        ranges = (AddressRange(base=0x40012000, end=0x40012400, peripheral=adc_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(adc_svd,), ranges=ranges)
        self.bus = PeripheralBus(amap)
        self.adc = Stm32AdcPeripheral(peripheral=adc_svd, irq=18)
        self.bus.register_peripheral("ADC1", self.adc)

        class _FakeEmu:
            symbols = SymbolTable()
            semihosting = SemihostingHandler()
            coverage_enabled = False
            _coverage = set()
            _coverage_hits = {}
            flash_base = 0x08000000
            flash_end = 0x08010000
            pc = 0x08000100
        self.cmds = Commands(emu=_FakeEmu(), bus=self.bus)

    def test_adc_list(self):
        out = self.cmds.cmd_adc(["list"])
        self.assertIn("ADC1", out)

    def test_adc_status(self):
        out = self.cmds.cmd_adc(["status", "ADC1"])
        self.assertIn("ADC1", out)
        self.assertIn("CR=", out)
        self.assertIn("DR=", out)

    def test_adc_sample(self):
        out = self.cmds.cmd_adc(["sample", "ADC1", "1234"])
        self.assertIn("queued", out)
        self.assertIn("queue=1", out)

    def test_adc_convert(self):
        self.adc.inject_sample(4095)
        self.adc.write(self.adc._CR, 4, self.adc._CR_ADEN)
        out = self.cmds.cmd_adc(["convert", "ADC1"])
        self.assertIn("conversion complete", out)
        self.assertIn("0FFF", out)

    def test_adc_usage(self):
        out = self.cmds.cmd_adc([])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
