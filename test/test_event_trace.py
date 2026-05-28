"""Tests for event trace capture and export."""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

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
    def emu_stop(self): pass
    def reg_read(self, reg): return 0
    def reg_write(self, reg, val): pass


class _TraceEmu:
    """Minimal emulator fake with event trace support."""

    def __init__(self, bus):
        self.bus = bus
        self.pc = 0x08000100
        self.uc = _FakeUc()
        self._running = False
        self._instruction_count = 0
        self.event_trace_enabled = False
        self._event_trace = []
        self._event_trace_max = 10000
        self._event_breakpoints = []
        self._event_bp_next_id = 1
        self.last_event_break = None
        self._timed_events = []
        self.rtos_trace_enabled = False
        self._rtos_switch_count = 0

    @property
    def instruction_count(self):
        return self._instruction_count

    def enable_event_trace(self, max_events=10000):
        self._event_trace_max = max_events
        self.event_trace_enabled = True
        self.bus.subscribe("*", self._on_trace_event)

    def disable_event_trace(self):
        self.event_trace_enabled = False
        self.bus.unsubscribe("*", self._on_trace_event)

    def _on_trace_event(self, event):
        if not self.event_trace_enabled:
            return
        entry = {
            "instruction": self._instruction_count,
            "pc": self.pc & 0xFFFFFFFF,
            "kind": event.kind,
            "source": getattr(event, "source", ""),
            "address": getattr(event, "address", 0),
        }
        payload = getattr(event, "payload", None)
        if payload is not None:
            entry["payload"] = payload
        self._event_trace.append(entry)
        if len(self._event_trace) > self._event_trace_max:
            self._event_trace = self._event_trace[-self._event_trace_max:]

    def event_trace_list(self, count=20):
        return list(self._event_trace[-count:])

    def event_trace_clear(self):
        n = len(self._event_trace)
        self._event_trace.clear()
        return n

    def event_trace_export(self, path):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for entry in self._event_trace:
                safe = {}
                for k, v in entry.items():
                    try:
                        json.dumps(v)
                        safe[k] = v
                    except (TypeError, ValueError):
                        safe[k] = str(v)
                f.write(json.dumps(safe) + "\n")
        return len(self._event_trace)

    def list_timed_events(self):
        return []

    def list_event_breakpoints(self):
        return []

    def rtos_status(self):
        return {"trace_enabled": False, "switch_count": 0, "psp": 0, "msp": 0,
                "control": 0, "active_exceptions": [], "exception_depth": 0,
                "instruction_count": 0, "in_handler": False}


def _make_bus():
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    return PeripheralBus(amap)


# ── Core event trace tests ────────────────────────────────────────


class EventTraceTests(unittest.TestCase):
    def test_events_captured_when_enabled(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        emu._instruction_count = 100
        bus.emit(PeripheralEvent(kind="timer_update", source="TIM2"))
        entries = emu.event_trace_list()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kind"], "timer_update")
        self.assertEqual(entries[0]["source"], "TIM2")
        self.assertEqual(entries[0]["instruction"], 100)

    def test_no_capture_when_disabled(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        bus.emit(PeripheralEvent(kind="test"))
        self.assertEqual(len(emu._event_trace), 0)

    def test_disable_stops_capture(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        bus.emit(PeripheralEvent(kind="a"))
        emu.disable_event_trace()
        bus.emit(PeripheralEvent(kind="b"))
        self.assertEqual(len(emu._event_trace), 1)

    def test_ring_buffer_truncation(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace(max_events=5)
        for i in range(10):
            emu._instruction_count = i
            bus.emit(PeripheralEvent(kind=f"evt_{i}"))
        self.assertEqual(len(emu._event_trace), 5)
        self.assertEqual(emu._event_trace[0]["kind"], "evt_5")

    def test_payload_captured(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        bus.emit(PeripheralEvent(
            kind="adc_eoc", source="ADC1",
            payload={"sample": 4095, "conversion": 1},
        ))
        entries = emu.event_trace_list()
        self.assertEqual(entries[0]["payload"]["sample"], 4095)

    def test_pc_captured(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.pc = 0x08001234
        emu.enable_event_trace()
        bus.emit(PeripheralEvent(kind="test"))
        self.assertEqual(emu._event_trace[0]["pc"], 0x08001234)

    def test_clear(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        bus.emit(PeripheralEvent(kind="a"))
        bus.emit(PeripheralEvent(kind="b"))
        count = emu.event_trace_clear()
        self.assertEqual(count, 2)
        self.assertEqual(len(emu._event_trace), 0)

    def test_list_returns_last_n(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        for i in range(10):
            bus.emit(PeripheralEvent(kind=f"evt_{i}"))
        last3 = emu.event_trace_list(3)
        self.assertEqual(len(last3), 3)
        self.assertEqual(last3[0]["kind"], "evt_7")

    def test_wildcard_captures_all_kinds(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        bus.emit(PeripheralEvent(kind="timer_update"))
        bus.emit(PeripheralEvent(kind="adc_eoc"))
        bus.emit(PeripheralEvent(kind="gpio_edge"))
        bus.emit(PeripheralEvent(kind="dma_complete"))
        bus.emit(PeripheralEvent(kind="rtos_exception"))
        self.assertEqual(len(emu._event_trace), 5)
        kinds = {e["kind"] for e in emu._event_trace}
        self.assertEqual(kinds, {"timer_update", "adc_eoc", "gpio_edge",
                                  "dma_complete", "rtos_exception"})


# ── JSONL export tests ────────────────────────────────────────────


class EventTraceExportTests(unittest.TestCase):
    def test_export_jsonl(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        emu.enable_event_trace()
        emu._instruction_count = 50
        bus.emit(PeripheralEvent(kind="timer_update", source="TIM2"))
        emu._instruction_count = 100
        bus.emit(PeripheralEvent(
            kind="adc_eoc", source="ADC1",
            payload={"sample": 3000},
        ))

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            count = emu.event_trace_export(path)
            self.assertEqual(count, 2)

            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 2)

            entry0 = json.loads(lines[0])
            self.assertEqual(entry0["kind"], "timer_update")
            self.assertEqual(entry0["instruction"], 50)
            self.assertEqual(entry0["source"], "TIM2")

            entry1 = json.loads(lines[1])
            self.assertEqual(entry1["kind"], "adc_eoc")
            self.assertEqual(entry1["payload"]["sample"], 3000)

    def test_export_empty(self):
        bus = _make_bus()
        emu = _TraceEmu(bus)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "empty.jsonl"
            count = emu.event_trace_export(path)
            self.assertEqual(count, 0)
            self.assertEqual(path.read_text(), "")


# ── Shell command tests ───────────────────────────────────────────


class EventTraceShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        self.bus = _make_bus()
        self.emu = _TraceEmu(self.bus)
        self.emu.symbols = SymbolTable()
        self.emu.semihosting = SemihostingHandler()
        self.emu.coverage_enabled = False
        self.emu._coverage = set()
        self.emu._coverage_hits = {}
        self.emu.flash_base = 0x08000000
        self.emu.flash_end = 0x08010000
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_events_on(self):
        out = self.cmds.cmd_events(["on"])
        self.assertIn("on", out)
        self.assertTrue(self.emu.event_trace_enabled)

    def test_events_off(self):
        self.cmds.cmd_events(["on"])
        out = self.cmds.cmd_events(["off"])
        self.assertIn("off", out)
        self.assertFalse(self.emu.event_trace_enabled)

    def test_events_list_empty(self):
        out = self.cmds.cmd_events(["list"])
        self.assertIn("no events", out)

    def test_events_list_with_data(self):
        self.cmds.cmd_events(["on"])
        self.bus.emit(PeripheralEvent(kind="test_event", source="TEST"))
        out = self.cmds.cmd_events(["list"])
        self.assertIn("test_event", out)
        self.assertIn("TEST", out)

    def test_events_clear(self):
        self.cmds.cmd_events(["on"])
        self.bus.emit(PeripheralEvent(kind="test"))
        out = self.cmds.cmd_events(["clear"])
        self.assertIn("cleared 1", out)

    def test_events_export(self):
        self.cmds.cmd_events(["on"])
        self.bus.emit(PeripheralEvent(kind="test"))
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "trace.jsonl")
            out = self.cmds.cmd_events(["export", path])
            self.assertIn("exported 1", out)

    def test_events_count(self):
        self.cmds.cmd_events(["on", "5000"])
        out = self.cmds.cmd_events(["count"])
        self.assertIn("max: 5000", out)

    def test_events_usage(self):
        out = self.cmds.cmd_events([])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
