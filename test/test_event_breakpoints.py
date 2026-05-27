"""Tests for event breakpoints."""
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
    _emu_mod = types.ModuleType("stmemu.core.emulator")
    class _PcRegWrite: pass
    class _Emulator: pass
    _emu_mod.PcRegWrite = _PcRegWrite
    _emu_mod.Emulator = _Emulator
    sys.modules["stmemu.core.emulator"] = _emu_mod

from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.svd.address_map import AddressMap


class _FakeUc:
    def emu_stop(self):
        pass


class _MinimalEmu:
    """Minimal emulator fake with event breakpoint support."""
    def __init__(self, bus):
        self.bus = bus
        self.pc = 0x08000100
        self.last_event_break = None
        self._event_breakpoints = []
        self._event_bp_next_id = 1
        self._running = False
        self.uc = _FakeUc()

    def add_event_breakpoint(self, kind, *, source=None, name=""):
        bp_id = self._event_bp_next_id
        self._event_bp_next_id += 1
        bp = {
            "id": bp_id, "kind": kind, "source": source,
            "name": name or f"evt:{kind}" + (f"/{source}" if source else ""),
            "enabled": True, "hits": 0,
        }
        self._event_breakpoints.append(bp)
        self.bus.subscribe(kind, self._on_event)
        return bp_id

    def remove_event_breakpoint(self, bp_id):
        before = len(self._event_breakpoints)
        self._event_breakpoints = [bp for bp in self._event_breakpoints if bp["id"] != bp_id]
        return len(self._event_breakpoints) < before

    def list_event_breakpoints(self):
        return [dict(bp) for bp in self._event_breakpoints]

    def clear_event_breakpoints(self):
        count = len(self._event_breakpoints)
        self._event_breakpoints.clear()
        return count

    def _on_event(self, event):
        if not self._running:
            return
        for bp in self._event_breakpoints:
            if not bp["enabled"]:
                continue
            if bp["kind"] != event.kind:
                continue
            if bp["source"] is not None and bp["source"].upper() != str(getattr(event, "source", "")).upper():
                continue
            bp["hits"] += 1
            self.last_event_break = {
                "bp_id": bp["id"], "kind": event.kind,
                "source": getattr(event, "source", ""),
                "address": getattr(event, "address", 0),
                "payload": getattr(event, "payload", None),
                "pc": self.pc,
            }
            self.uc.emu_stop()
            return


def _make_bus():
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    return PeripheralBus(amap)


# ── Core event breakpoint tests ──────────────────────────────────


class EventBreakpointTests(unittest.TestCase):
    def test_add_and_list(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        bp_id = emu.add_event_breakpoint("timer_update")
        bps = emu.list_event_breakpoints()
        self.assertEqual(len(bps), 1)
        self.assertEqual(bps[0]["id"], bp_id)
        self.assertEqual(bps[0]["kind"], "timer_update")

    def test_matching_event_triggers_break(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("timer_update")
        emu._running = True
        bus.emit(PeripheralEvent(kind="timer_update", source="TIM2"))
        self.assertIsNotNone(emu.last_event_break)
        self.assertEqual(emu.last_event_break["kind"], "timer_update")
        self.assertEqual(emu.last_event_break["source"], "TIM2")

    def test_non_matching_kind_no_break(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("timer_update")
        emu._running = True
        bus.emit(PeripheralEvent(kind="adc_eoc", source="ADC1"))
        self.assertIsNone(emu.last_event_break)

    def test_source_filter(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("gpio_edge", source="GPIOA")
        emu._running = True

        bus.emit(PeripheralEvent(kind="gpio_edge", source="GPIOB"))
        self.assertIsNone(emu.last_event_break)

        bus.emit(PeripheralEvent(kind="gpio_edge", source="GPIOA"))
        self.assertIsNotNone(emu.last_event_break)
        self.assertEqual(emu.last_event_break["source"], "GPIOA")

    def test_source_filter_case_insensitive(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("adc_eoc", source="adc1")
        emu._running = True
        bus.emit(PeripheralEvent(kind="adc_eoc", source="ADC1"))
        self.assertIsNotNone(emu.last_event_break)

    def test_no_break_when_not_running(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("timer_update")
        emu._running = False
        bus.emit(PeripheralEvent(kind="timer_update", source="TIM2"))
        self.assertIsNone(emu.last_event_break)

    def test_hit_count(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        bp_id = emu.add_event_breakpoint("timer_update")
        emu._running = True
        bus.emit(PeripheralEvent(kind="timer_update"))
        bus.emit(PeripheralEvent(kind="timer_update"))
        bps = emu.list_event_breakpoints()
        self.assertEqual(bps[0]["hits"], 2)

    def test_remove(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        bp_id = emu.add_event_breakpoint("timer_update")
        self.assertTrue(emu.remove_event_breakpoint(bp_id))
        self.assertEqual(len(emu.list_event_breakpoints()), 0)
        self.assertFalse(emu.remove_event_breakpoint(999))

    def test_clear(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("a")
        emu.add_event_breakpoint("b")
        count = emu.clear_event_breakpoints()
        self.assertEqual(count, 2)
        self.assertEqual(len(emu.list_event_breakpoints()), 0)

    def test_payload_captured(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.add_event_breakpoint("adc_eoc")
        emu._running = True
        bus.emit(PeripheralEvent(
            kind="adc_eoc", source="ADC1",
            payload={"sample": 4095, "conversion": 1},
        ))
        self.assertEqual(emu.last_event_break["payload"]["sample"], 4095)

    def test_pc_captured(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        emu.pc = 0x08001234
        emu.add_event_breakpoint("timer_update")
        emu._running = True
        bus.emit(PeripheralEvent(kind="timer_update"))
        self.assertEqual(emu.last_event_break["pc"], 0x08001234)

    def test_multiple_breakpoints_first_match_wins(self):
        bus = _make_bus()
        emu = _MinimalEmu(bus)
        id1 = emu.add_event_breakpoint("timer_update", source="TIM2")
        id2 = emu.add_event_breakpoint("timer_update")
        emu._running = True
        bus.emit(PeripheralEvent(kind="timer_update", source="TIM2"))
        self.assertEqual(emu.last_event_break["bp_id"], id1)


# ── Shell command tests ───────────────────────────────────────────


class EventBreakShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
        self.bus = PeripheralBus(amap)
        self.emu = _MinimalEmu(self.bus)
        self.emu.symbols = SymbolTable()
        self.emu.semihosting = SemihostingHandler()
        self.emu.coverage_enabled = False
        self.emu._coverage = set()
        self.emu._coverage_hits = {}
        self.emu.flash_base = 0x08000000
        self.emu.flash_end = 0x08010000
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_break_event_add(self):
        out = self.cmds.cmd_break(["event", "timer_update"])
        self.assertIn("added event breakpoint", out)
        self.assertIn("timer_update", out)

    def test_break_event_add_with_source(self):
        out = self.cmds.cmd_break(["event", "gpio_edge", "source=GPIOA"])
        self.assertIn("GPIOA", out)

    def test_break_event_list(self):
        self.cmds.cmd_break(["event", "timer_update"])
        out = self.cmds.cmd_break(["event", "list"])
        self.assertIn("timer_update", out)
        self.assertIn("#1", out)

    def test_break_event_list_empty(self):
        out = self.cmds.cmd_break(["event", "list"])
        self.assertIn("no event breakpoints", out)

    def test_break_event_remove(self):
        self.cmds.cmd_break(["event", "timer_update"])
        out = self.cmds.cmd_break(["event", "remove", "1"])
        self.assertIn("removed", out)

    def test_break_event_clear(self):
        self.cmds.cmd_break(["event", "timer_update"])
        self.cmds.cmd_break(["event", "adc_eoc"])
        out = self.cmds.cmd_break(["event", "clear"])
        self.assertIn("cleared 2", out)

    def test_break_event_usage(self):
        out = self.cmds.cmd_break([])
        self.assertIn("usage:", out)

    def test_format_event_break(self):
        eb = {
            "bp_id": 1, "kind": "timer_update", "source": "TIM2",
            "pc": 0x08001234, "payload": {"cnt": 0, "arr": 999},
        }
        from stmemu.shell.commands import Commands
        text = Commands._format_event_break(eb)
        self.assertIn("EVENT BP HIT", text)
        self.assertIn("timer_update", text)
        self.assertIn("TIM2", text)
        self.assertIn("0x08001234", text)


if __name__ == "__main__":
    unittest.main()
