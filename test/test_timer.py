"""Tests for timer update events, UIF, IRQ, and shell commands."""
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
from stmemu.peripherals.timer import BasicTimerPeripheral


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


def _make_bus_timer():
    tim_svd = _make_svd("TIM2", 0x40000000, _TIMER_REGS,
        interrupts=(SvdInterrupt(name="TIM2", value=28),))
    ranges = (AddressRange(base=0x40000000, end=0x40000400, peripheral=tim_svd),)
    amap = AddressMap(device_name="TEST", peripherals=(tim_svd,), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    tim = BasicTimerPeripheral(peripheral=tim_svd, irq=28)
    bus.register_peripheral("TIM2", tim)
    return bus, tim, nvic


# ── Update event tests ────────────────────────────────────────────


class TimerUpdateTests(unittest.TestCase):
    def test_overflow_sets_uif(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write_register_value(tim._PSC, 0)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        sr = tim.read_register_value(tim._SR)
        self.assertTrue(sr & tim._SR_UIF)

    def test_no_uif_before_overflow(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 99)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(50)
        sr = tim.read_register_value(tim._SR)
        self.assertFalse(sr & tim._SR_UIF)

    def test_cnt_wraps_on_overflow(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(12)
        cnt = tim.read_register_value(tim._CNT)
        self.assertEqual(cnt, 2)

    def test_sr_uif_clear_write_zero(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertTrue(tim.read_register_value(tim._SR) & tim._SR_UIF)
        tim.write(tim._SR, 4, ~tim._SR_UIF & 0xFFFFFFFF)
        self.assertFalse(tim.read_register_value(tim._SR) & tim._SR_UIF)

    def test_sr_halfword_clear_is_write_zero(self):
        # A halfword (STRH) write to SR must keep rc_w0 semantics: writing 0
        # clears a flag, writing 1 keeps it — it must NOT behave like a plain
        # read/write register and spuriously set the other bits.
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._SR, tim._SR_UIF | tim._SR_CC1IF)
        tim.write(tim._SR, 2, ~tim._SR_UIF & 0xFFFF)
        sr = tim.read_register_value(tim._SR)
        self.assertFalse(sr & tim._SR_UIF)   # UIF cleared (wrote 0)
        self.assertTrue(sr & tim._SR_CC1IF)  # CC1IF kept (wrote 1)
        self.assertEqual(sr & ~tim._SR_CC1IF, 0)  # nothing else got set

    def test_egr_ug_sets_uif_and_clears_cnt(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._CNT, 50)
        tim.write(tim._EGR, 4, tim._EGR_UG)
        self.assertEqual(tim.read_register_value(tim._CNT), 0)
        self.assertTrue(tim.read_register_value(tim._SR) & tim._SR_UIF)

    def test_prescaler_divides_ticks(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write_register_value(tim._PSC, 3)  # divider = 4
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(40)  # 40 / 4 = 10 steps → overflow
        self.assertTrue(tim.read_register_value(tim._SR) & tim._SR_UIF)

    def test_disabled_timer_does_not_count(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.tick(100)
        self.assertEqual(tim.read_register_value(tim._CNT), 0)

    def test_one_pulse_mode_stops_after_overflow(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN | tim._CR1_OPM)
        tim.tick(10)
        self.assertTrue(tim.read_register_value(tim._SR) & tim._SR_UIF)
        cr1 = tim.read_register_value(tim._CR1)
        self.assertFalse(cr1 & tim._CR1_CEN)


# ── Event tests ───────────────────────────────────────────────────


class TimerEventTests(unittest.TestCase):
    def test_timer_update_event_emitted(self):
        bus, tim, nvic = _make_bus_timer()
        bus.event_log_enabled = True
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        log = bus.drain_event_log()
        updates = [e for e in log if e.kind == "timer_update"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0].source, "TIM2")
        self.assertEqual(updates[0].payload["update_count"], 1)

    def test_egr_ug_emits_event(self):
        bus, tim, nvic = _make_bus_timer()
        bus.event_log_enabled = True
        tim.write(tim._EGR, 4, tim._EGR_UG)
        log = bus.drain_event_log()
        updates = [e for e in log if e.kind == "timer_update"]
        self.assertEqual(len(updates), 1)

    def test_no_event_without_overflow(self):
        bus, tim, nvic = _make_bus_timer()
        bus.event_log_enabled = True
        tim.write_register_value(tim._ARR, 99)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(50)
        log = bus.drain_event_log()
        updates = [e for e in log if e.kind == "timer_update"]
        self.assertEqual(len(updates), 0)

    def test_subscribe_to_timer_update(self):
        bus, tim, nvic = _make_bus_timer()
        received = []
        bus.subscribe("timer_update", received.append)
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertEqual(len(received), 1)


# ── IRQ tests ─────────────────────────────────────────────────────


class TimerIrqTests(unittest.TestCase):
    def test_uie_pends_irq_on_overflow(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._DIER, 4, tim._DIER_UIE)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertTrue(nvic.pending.get(28, False))

    def test_no_irq_without_uie(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertFalse(nvic.pending.get(28, False))

    def test_clearing_uif_clears_irq(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._DIER, 4, tim._DIER_UIE)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        self.assertTrue(nvic.pending.get(28, False))
        tim.write(tim._SR, 4, ~tim._SR_UIF & 0xFFFFFFFF)
        self.assertFalse(nvic.pending.get(28, False))

    def test_egr_ug_with_uie_pends_irq(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write(tim._DIER, 4, tim._DIER_UIE)
        tim.write(tim._EGR, 4, tim._EGR_UG)
        self.assertTrue(nvic.pending.get(28, False))


# ── Snapshot tests ────────────────────────────────────────────────


class TimerSnapshotTests(unittest.TestCase):
    def test_snapshot_restore(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 99)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(50)
        state = tim.snapshot_state()
        old_cnt = tim.read_register_value(tim._CNT)
        tim.reset()
        self.assertEqual(tim.read_register_value(tim._CNT), 0)
        tim.restore_state(state)
        self.assertEqual(tim.read_register_value(tim._CNT), old_cnt)
        self.assertEqual(tim._update_count, 0)

    def test_update_count_in_snapshot(self):
        bus, tim, nvic = _make_bus_timer()
        tim.write_register_value(tim._ARR, 9)
        tim.write(tim._CR1, 4, tim._CR1_CEN)
        tim.tick(10)
        state = tim.snapshot_state()
        self.assertEqual(state["update_count"], 1)
        tim.reset()
        tim.restore_state(state)
        self.assertEqual(tim._update_count, 1)


# ── Shell command tests ───────────────────────────────────────────


class TimerShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        tim_svd = _make_svd("TIM2", 0x40000000, _TIMER_REGS,
            interrupts=(SvdInterrupt(name="TIM2", value=28),))
        ranges = (AddressRange(base=0x40000000, end=0x40000400, peripheral=tim_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(tim_svd,), ranges=ranges)
        self.bus = PeripheralBus(amap)
        self.tim = BasicTimerPeripheral(peripheral=tim_svd, irq=28)
        self.bus.register_peripheral("TIM2", self.tim)

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

    def test_timer_list(self):
        out = self.cmds.cmd_timer(["list"])
        self.assertIn("TIM2", out)

    def test_timer_status(self):
        self.tim.write_register_value(self.tim._ARR, 999)
        out = self.cmds.cmd_timer(["status", "TIM2"])
        self.assertIn("TIM2", out)
        self.assertIn("ARR=999", out)

    def test_timer_tick(self):
        self.tim.write_register_value(self.tim._ARR, 9)
        self.tim.write(self.tim._CR1, 4, self.tim._CR1_CEN)
        out = self.cmds.cmd_timer(["tick", "TIM2", "5"])
        self.assertIn("ticked 5 cycles", out)
        self.assertIn("CNT=5", out)

    def test_timer_force_update(self):
        self.tim.write_register_value(self.tim._CNT, 42)
        out = self.cmds.cmd_timer(["force_update", "TIM2"])
        self.assertIn("update forced", out)
        self.assertIn("CNT=0", out)

    def test_timer_usage(self):
        out = self.cmds.cmd_timer([])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
