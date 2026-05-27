"""Tests for RTOS task awareness and context switch tracing."""
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
from stmemu.peripherals.core_cm import CortexMCorePeripheral


class _FakeUc:
    def emu_stop(self):
        pass
    def reg_read(self, reg):
        return 0
    def reg_write(self, reg, val):
        pass
    def mem_read(self, addr, size):
        return b"\x00" * size
    def mem_write(self, addr, data):
        pass
    def emu_start(self, addr, end, count=1):
        pass
    def hook_add(self, *a, **k):
        return 0


class _RtosEmu:
    """Minimal emulator fake with RTOS tracing support."""

    def __init__(self, bus):
        self.bus = bus
        self.pc = 0x08000100
        self.uc = _FakeUc()
        self._running = False
        self._instruction_count = 0
        self._exception_stack = []
        self._exception_return_stack = []
        self.rtos_trace_enabled = False
        self._rtos_switch_count = 0
        self._rtos_last_psp = 0
        self._psp = 0x20001000
        self._msp = 0x20002000
        self._control = 0
        self.core_peripheral = CortexMCorePeripheral(vtor=0x08000000)
        self.last_event_break = None
        self._event_breakpoints = []
        self._event_bp_next_id = 1

    def _read_psp(self):
        return self._psp

    def _read_msp(self):
        return self._msp

    def _read_control(self):
        return self._control

    def _emit_rtos_exception_event(self, exc_num, phase):
        if not self.rtos_trace_enabled:
            return
        exc_name = self.core_peripheral.exception_name(exc_num)
        self.bus.emit(PeripheralEvent(
            kind="rtos_exception",
            source=exc_name,
            payload={
                "exception": exc_name,
                "exc_num": exc_num,
                "phase": phase,
                "pc": self.pc,
                "msp": self._msp,
                "psp": self._psp,
                "control": self._control,
                "active_depth": len(self._exception_stack),
                "instruction": self._instruction_count,
            },
        ))

    def _emit_rtos_context_switch(self, exc_num, old_psp, new_psp):
        if not self.rtos_trace_enabled:
            return
        self._rtos_switch_count += 1
        self.bus.emit(PeripheralEvent(
            kind="rtos_context_switch",
            source="PendSV",
            payload={
                "switch_count": self._rtos_switch_count,
                "old_psp": old_psp,
                "new_psp": new_psp,
                "msp": self._msp,
                "control": self._control,
                "pc": self.pc,
                "instruction": self._instruction_count,
            },
        ))

    def simulate_enter_exception(self, exc_num):
        self._exception_stack.append(exc_num)
        self.core_peripheral.enter_exception(exc_num)
        self._emit_rtos_exception_event(exc_num, "enter")
        if exc_num == 14:
            self._rtos_last_psp = self._psp

    def simulate_exit_exception(self, exc_num, new_psp=None):
        if self._exception_stack and self._exception_stack[-1] == exc_num:
            self._exception_stack.pop()
        self.core_peripheral.exit_exception(exc_num)
        if new_psp is not None:
            old_psp = self._psp
            self._psp = new_psp
        self._emit_rtos_exception_event(exc_num, "exit")
        if exc_num == 14:
            new_p = self._psp
            if new_p != self._rtos_last_psp and self._rtos_last_psp != 0:
                self._emit_rtos_context_switch(exc_num, self._rtos_last_psp, new_p)

    def rtos_status(self):
        return {
            "trace_enabled": self.rtos_trace_enabled,
            "switch_count": self._rtos_switch_count,
            "psp": self._psp,
            "msp": self._msp,
            "control": self._control,
            "active_exceptions": list(self._exception_stack),
            "exception_depth": len(self._exception_stack),
            "instruction_count": self._instruction_count,
            "in_handler": bool(self._exception_stack),
        }


def _make_bus():
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    return PeripheralBus(amap)


# ── RTOS tracing tests ────────────────────────────────────────────


class RtosTracingTests(unittest.TestCase):
    def test_exception_enter_emits_event(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu.simulate_enter_exception(15)  # SysTick
        log = bus.drain_event_log()
        exc_events = [e for e in log if e.kind == "rtos_exception"]
        self.assertEqual(len(exc_events), 1)
        self.assertEqual(exc_events[0].source, "SysTick")
        self.assertEqual(exc_events[0].payload["phase"], "enter")

    def test_exception_exit_emits_event(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu.simulate_enter_exception(15)
        bus.drain_event_log()
        emu.simulate_exit_exception(15)
        log = bus.drain_event_log()
        exc_events = [e for e in log if e.kind == "rtos_exception"]
        self.assertEqual(len(exc_events), 1)
        self.assertEqual(exc_events[0].payload["phase"], "exit")

    def test_no_events_when_trace_disabled(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = False
        emu.simulate_enter_exception(14)
        emu.simulate_exit_exception(14, new_psp=0x20003000)
        log = bus.drain_event_log()
        self.assertEqual(len(log), 0)

    def test_pendsv_context_switch_detected(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu._psp = 0x20001000

        emu.simulate_enter_exception(14)  # PendSV
        emu.simulate_exit_exception(14, new_psp=0x20003000)

        log = bus.drain_event_log()
        switches = [e for e in log if e.kind == "rtos_context_switch"]
        self.assertEqual(len(switches), 1)
        self.assertEqual(switches[0].payload["old_psp"], 0x20001000)
        self.assertEqual(switches[0].payload["new_psp"], 0x20003000)

    def test_no_context_switch_when_psp_unchanged(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu._psp = 0x20001000

        emu.simulate_enter_exception(14)
        emu.simulate_exit_exception(14)  # PSP unchanged

        log = bus.drain_event_log()
        switches = [e for e in log if e.kind == "rtos_context_switch"]
        self.assertEqual(len(switches), 0)

    def test_systick_no_context_switch(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True

        emu.simulate_enter_exception(15)
        emu.simulate_exit_exception(15, new_psp=0x20005000)

        log = bus.drain_event_log()
        switches = [e for e in log if e.kind == "rtos_context_switch"]
        self.assertEqual(len(switches), 0, "SysTick should not trigger context_switch")

    def test_svc_traced(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True

        emu.simulate_enter_exception(11)  # SVC
        log = bus.drain_event_log()
        exc_events = [e for e in log if e.kind == "rtos_exception"]
        self.assertEqual(len(exc_events), 1)
        self.assertEqual(exc_events[0].source, "SVC")

    def test_switch_count_increments(self):
        bus = _make_bus()
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu._psp = 0x20001000

        emu.simulate_enter_exception(14)
        emu.simulate_exit_exception(14, new_psp=0x20002000)
        self.assertEqual(emu._rtos_switch_count, 1)

        emu.simulate_enter_exception(14)
        emu.simulate_exit_exception(14, new_psp=0x20001000)
        self.assertEqual(emu._rtos_switch_count, 2)

    def test_event_payload_includes_stacks(self):
        bus = _make_bus()
        bus.event_log_enabled = True
        emu = _RtosEmu(bus)
        emu.rtos_trace_enabled = True
        emu._psp = 0x20001000
        emu._msp = 0x20008000

        emu.simulate_enter_exception(14)
        log = bus.drain_event_log()
        p = log[0].payload
        self.assertEqual(p["psp"], 0x20001000)
        self.assertEqual(p["msp"], 0x20008000)
        self.assertIn("active_depth", p)
        self.assertIn("instruction", p)


# ── RTOS status tests ────────────────────────────────────────────


class RtosStatusTests(unittest.TestCase):
    def test_rtos_status(self):
        bus = _make_bus()
        emu = _RtosEmu(bus)
        emu._psp = 0x20001000
        emu._msp = 0x20008000
        emu._rtos_switch_count = 5
        emu._instruction_count = 100000
        s = emu.rtos_status()
        self.assertEqual(s["psp"], 0x20001000)
        self.assertEqual(s["msp"], 0x20008000)
        self.assertEqual(s["switch_count"], 5)
        self.assertFalse(s["in_handler"])

    def test_rtos_status_in_handler(self):
        bus = _make_bus()
        emu = _RtosEmu(bus)
        emu.simulate_enter_exception(14)
        s = emu.rtos_status()
        self.assertTrue(s["in_handler"])
        self.assertEqual(s["exception_depth"], 1)


# ── Shell command tests ───────────────────────────────────────────


class RtosShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        bus = _make_bus()
        self.emu = _RtosEmu(bus)
        self.emu.symbols = SymbolTable()
        self.emu.semihosting = SemihostingHandler()
        self.emu.coverage_enabled = False
        self.emu._coverage = set()
        self.emu._coverage_hits = {}
        self.emu.flash_base = 0x08000000
        self.emu.flash_end = 0x08010000
        self.cmds = Commands(emu=self.emu, bus=bus)

    def test_rtos_status_command(self):
        out = self.cmds.cmd_rtos(["status"])
        self.assertIn("trace:", out)
        self.assertIn("PSP:", out)
        self.assertIn("MSP:", out)

    def test_rtos_trace_on_off(self):
        out = self.cmds.cmd_rtos(["trace", "on"])
        self.assertIn("on", out)
        self.assertTrue(self.emu.rtos_trace_enabled)

        out = self.cmds.cmd_rtos(["trace", "off"])
        self.assertIn("off", out)
        self.assertFalse(self.emu.rtos_trace_enabled)

    def test_rtos_usage(self):
        out = self.cmds.cmd_rtos([])
        self.assertIn("usage:", out)

    def test_rtos_status_with_active_exception(self):
        self.emu.simulate_enter_exception(14)
        out = self.cmds.cmd_rtos(["status"])
        self.assertIn("PendSV", out)
        self.assertIn("in handler: yes", out)


if __name__ == "__main__":
    unittest.main()
