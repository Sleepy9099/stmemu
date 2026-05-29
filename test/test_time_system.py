"""Central emulated-time service tests.

advance_time() is the one path that moves time; idle fast-forward, per-instruction
stepping, cycle/instruction-scheduled events, and DWT all flow through it.
"""
from __future__ import annotations

import sys
import unittest

from stmemu.core.loader import FirmwareSegment
from stmemu.core.time_engine import EmulatedTime
from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.core_cm import CortexMCorePeripheral
from stmemu.svd.address_map import AddressMap


FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000

# movs r0,#1 ; movs r1,#2 ; movs r2,#3 ; b .  (self-branch idle)
_PROGRAM = bytes([0x01, 0x20, 0x02, 0x21, 0x03, 0x22, 0xFE, 0xE7])


def _load_real_emulator_class():
    for name in (
        "stmemu.core.emulator", "stmemu.core.disasm",
        "unicorn.arm_const", "unicorn.unicorn_const", "unicorn", "capstone",
    ):
        sys.modules.pop(name, None)
    from stmemu.core.emulator import Emulator
    return Emulator


def _make_emu(program: bytes = _PROGRAM):
    Emulator = _load_real_emulator_class()
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    bus = PeripheralBus(amap)
    emu = Emulator(
        bus=bus, flash_base=FLASH_BASE,
        firmware_segments=(FirmwareSegment(address=FLASH_BASE, data=program),),
        sram_base=SRAM_BASE, sram_size=SRAM_SIZE,
    )
    emu.write_reg("pc", FLASH_BASE | 1)
    emu.write_reg("sp", SRAM_BASE + 0x10000)
    return emu


class _IrqIn(PeripheralModel):
    """Stub peripheral that reports a fixed cycles-until-IRQ."""

    def __init__(self, cycles):
        self._c = cycles

    def read(self, offset, size):
        return 0

    def write(self, offset, size, value):
        pass

    def cycles_until_irq(self):
        return self._c


class EmulatedTimeUnitTests(unittest.TestCase):
    def test_idle_fast_forward_by_mode(self):
        self.assertTrue(EmulatedTime(mode="idle").idle_fast_forward)
        self.assertTrue(EmulatedTime(mode="adaptive").idle_fast_forward)
        self.assertFalse(EmulatedTime(mode="normal").idle_fast_forward)
        self.assertFalse(EmulatedTime(mode="fixed").idle_fast_forward)

    def test_ms_to_cycles(self):
        t = EmulatedTime(cycle_hz=1_000_000)
        self.assertEqual(t.ms_to_cycles(1), 1000)
        self.assertEqual(t.ms_to_cycles(0.25), 250)


class AdvanceTimeTests(unittest.TestCase):
    def test_advance_time_increments_cycle_counter(self):
        emu = _make_emu()
        self.assertEqual(emu.time.cycles, 0)
        emu.advance_time(100, reason="manual")
        self.assertEqual(emu.time.cycles, 100)
        emu.advance_time(50)
        self.assertEqual(emu.time.cycles, 150)

    def test_advance_time_ticks_bus_by_same_amount(self):
        # Peripheral clock ticks ride the unified cycle count.
        emu = _make_emu()
        ticks = []

        class _Rec(PeripheralModel):
            def read(self, o, s): return 0
            def write(self, o, s, v): pass
            def tick(self, cycles): ticks.append(cycles)

        emu.bus.mount(name="REC", base=0x40009000, size=0x100, model=_Rec())
        emu.advance_time(77)
        self.assertEqual(ticks, [77])
        self.assertEqual(emu.time.cycles, 77)

    def test_instruction_step_advances_by_tick_scale(self):
        emu = _make_emu()
        emu.tick_scale = 1
        emu.step(3)  # the 3 movs (PC changes each -> no idle skip)
        self.assertEqual(emu.time.instructions, 3)
        self.assertEqual(emu.time.cycles, 3)

    def test_idle_fast_forward_routes_through_advance_time(self):
        emu = _make_emu()
        emu.bus.mount(name="IRQIN", base=0x4000A000, size=0x100, model=_IrqIn(5000))
        before = emu.time.cycles
        emu._idle_fast_forward()
        self.assertEqual(emu.time.cycles, before + 5000)

    def test_idle_fast_forward_capped(self):
        emu = _make_emu()
        emu.time.max_fast_forward_cycles = 1000
        emu.bus.mount(name="IRQIN", base=0x4000B000, size=0x100, model=_IrqIn(10_000_000))
        emu._idle_fast_forward()
        self.assertEqual(emu.time.cycles, 1000)


class TimedEventTests(unittest.TestCase):
    def test_cycle_deadline_event_fires(self):
        emu = _make_emu()
        seen = []
        emu.bus.subscribe("ff_evt", lambda e: seen.append(e))
        emu.add_timed_event_cycle(50, "event_emit", kind="ff_evt", source="t")
        emu.advance_time(49)
        self.assertEqual(seen, [], "not due yet")
        emu.advance_time(1)
        self.assertEqual(len(seen), 1, "fires at the cycle deadline")
        self.assertEqual(emu.list_timed_events(), [], "consumed")

    def test_after_ms_event_fires(self):
        emu = _make_emu()
        emu.time.cycle_hz = 1_000_000  # 1ms = 1000 cycles
        seen = []
        emu.bus.subscribe("ms_evt", lambda e: seen.append(e))
        emu.add_timed_event_ms(2, "event_emit", kind="ms_evt", source="t")
        emu.advance_time(1999)
        self.assertEqual(seen, [])
        emu.advance_time(1)
        self.assertEqual(len(seen), 1)

    def test_instruction_deadline_event_still_works(self):
        emu = _make_emu()
        seen = []
        emu.bus.subscribe("insn_evt", lambda e: seen.append(e))
        emu.add_timed_event(2, "event_emit", kind="insn_evt", source="t")
        emu.step(2)  # two instructions -> instruction deadline reached
        self.assertEqual(len(seen), 1)

    def test_idle_fast_forward_stops_at_cycle_event_before_irq(self):
        # Idle fast-forward must stop at a cycle-event deadline that falls
        # before the next IRQ, firing it at its proper time (not after leaping
        # to the IRQ) -- the event may inject input / pend an IRQ.
        emu = _make_emu()
        emu.bus.mount(name="IRQIN", base=0x4000C000, size=0x100, model=_IrqIn(100_000))
        seen = []
        emu.bus.subscribe("early", lambda e: seen.append(e))
        emu.add_timed_event_cycle(40_000, "event_emit", kind="early", source="t")
        emu._idle_fast_forward()
        self.assertEqual(emu.time.cycles, 40_000, "stops at the event deadline")
        self.assertEqual(len(seen), 1)

    def test_idle_fast_forward_targets_irq_when_no_earlier_event(self):
        # With the event after the IRQ, the jump targets the IRQ first.
        emu = _make_emu()
        emu.bus.mount(name="IRQIN", base=0x4000D000, size=0x100, model=_IrqIn(20_000))
        emu.add_timed_event_cycle(80_000, "event_emit", kind="late", source="t")
        emu._idle_fast_forward()
        self.assertEqual(emu.time.cycles, 20_000, "stops at the nearer IRQ")


class DwtUnifiedTimeTests(unittest.TestCase):
    def test_cyccnt_follows_unified_cycle_time(self):
        emu = _make_emu()
        core = CortexMCorePeripheral(vtor=FLASH_BASE)
        # Enable DWT cycle counter (DEMCR.TRCENA + DWT_CTRL.CYCCNTENA).
        core.write(0xEDFC, 4, 1 << 24)
        core.write(0x1000, 4, 1 << 0)
        emu.bus.mount(name="CORE", base=0xE0000000, size=0x10000, model=core)

        emu.advance_time(1234)
        self.assertEqual(core.read_register_value(0x1004), 1234)
        self.assertEqual(emu.time.cycles, 1234, "DWT CYCCNT == unified cycle time")


class BoardConfigTimeTests(unittest.TestCase):
    def test_emulator_time_settings(self):
        from stmemu.board_config import apply_board_config
        emu = _make_emu()
        cfg = {"emulator": {"time": {
            "mode": "normal", "tick_scale": 4,
            "max_fast_forward_cycles": 1234,
            "coalesce_timer_events": False, "cycle_hz": 2_000_000,
        }}}
        msgs = apply_board_config(cfg, emu.bus, emu, source="t")
        self.assertFalse(any("warning" in m for m in msgs), msgs)
        self.assertEqual(emu.time.mode, "normal")
        self.assertEqual(emu.tick_scale, 4)
        self.assertEqual(emu.time.max_fast_forward_cycles, 1234)
        self.assertFalse(emu.time.coalesce_timer_events)
        self.assertEqual(emu.time.cycle_hz, 2_000_000)

    def test_timed_events_by_cycle_and_instruction_config(self):
        from stmemu.board_config import apply_board_config
        emu = _make_emu()
        cfg = {"timed_events": [
            {"at_cycle": 500, "action": "event_emit", "kind": "c", "source": "t"},
            {"at_instruction": 10, "action": "event_emit", "kind": "i", "source": "t"},
            {"after_ms": 1, "action": "event_emit", "kind": "m", "source": "t"},
        ]}
        msgs = apply_board_config(cfg, emu.bus, emu, source="t")
        self.assertFalse(any("warning" in m for m in msgs), msgs)
        evts = emu.list_timed_events()
        self.assertEqual(len(evts), 3)
        self.assertTrue(any(e.get("at_cycle") == 500 for e in evts))
        self.assertTrue(any(e.get("at") == 10 for e in evts))
        # after_ms 1ms at the default 1MHz nominal clock -> 1000 cycles.
        self.assertTrue(any(e.get("at_cycle") == 1000 for e in evts))


if __name__ == "__main__":
    unittest.main()
