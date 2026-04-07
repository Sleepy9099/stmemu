"""Tests for symbol table, semihosting, coverage, and field decode features."""
from __future__ import annotations

import sys
import types
import unittest
from dataclasses import dataclass


# ── Stub external dependencies the same way test_shell_commands does ──

_MODULE_BACKUP: dict[str, object] = {}


def _set_module(name: str, module: object) -> None:
    if name not in _MODULE_BACKUP:
        _MODULE_BACKUP[name] = sys.modules.get(name)
    sys.modules[name] = module


if "capstone" not in sys.modules:
    capstone_stub = types.ModuleType("capstone")

    class _Cs:
        def __init__(self, *args, **kwargs) -> None:
            self.detail = False

        def disasm(self, code, addr, count=0):
            return []

    capstone_stub.Cs = _Cs
    capstone_stub.CS_ARCH_ARM = 0
    capstone_stub.CS_MODE_THUMB = 0
    _set_module("capstone", capstone_stub)

if "unicorn" not in sys.modules:
    unicorn_stub = types.ModuleType("unicorn")
    unicorn_const_stub = types.ModuleType("unicorn.unicorn_const")
    unicorn_const_stub.UC_HOOK_CODE = 0
    unicorn_stub.unicorn_const = unicorn_const_stub
    _set_module("unicorn", unicorn_stub)
    _set_module("unicorn.unicorn_const", unicorn_const_stub)

if "stmemu.core.emulator" not in sys.modules:
    emu_stub = types.ModuleType("stmemu.core.emulator")

    @dataclass
    class _PcRegWrite:
        pc: int
        peripheral: str
        register: str
        value: int
        cond: object = None

    class _Emulator:
        pass

    emu_stub.PcRegWrite = _PcRegWrite
    emu_stub.Emulator = _Emulator
    _set_module("stmemu.core.emulator", emu_stub)


from stmemu.core.symbols import SymbolTable, Symbol
from stmemu.core.semihosting import SemihostingHandler
from stmemu.svd.model import SvdField, SvdRegister, SvdPeripheral
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.shell.commands import Commands


# ── Minimal fakes ──


class _FakeEmu:
    def __init__(self) -> None:
        self.symbols = SymbolTable()
        self.semihosting = SemihostingHandler()
        self.coverage_enabled = False
        self._coverage: set[int] = set()
        self.pc = 0


class _FakeBus:
    def __init__(self, amap=None):
        self.amap = amap

    def read(self, addr, size):
        return 0

    def model_for_name(self, name):
        return None


# ── Symbol Table Tests ──────────────────────────────────────────────


class SymbolTableTests(unittest.TestCase):
    def setUp(self):
        self.table = SymbolTable()
        syms = [
            Symbol("main", 0x08000100, 64, "func"),
            Symbol("HAL_Init", 0x08000200, 128, "func"),
            Symbol("SystemClock_Config", 0x08000300, 256, "func"),
            Symbol("counter", 0x20000000, 4, "object"),
        ]
        for s in syms:
            self.table._by_name[s.name] = s
            self.table._by_addr[s.address] = s
        self.table._func_addrs = sorted(
            s.address for s in syms if s.sym_type == "func"
        )

    def test_lookup_name(self):
        s = self.table.lookup_name("main")
        self.assertIsNotNone(s)
        self.assertEqual(s.address, 0x08000100)

    def test_lookup_name_missing(self):
        self.assertIsNone(self.table.lookup_name("nonexistent"))

    def test_lookup_addr(self):
        s = self.table.lookup_addr(0x08000200)
        self.assertIsNotNone(s)
        self.assertEqual(s.name, "HAL_Init")

    def test_lookup_addr_with_thumb_bit(self):
        s = self.table.lookup_addr(0x08000201)
        self.assertIsNotNone(s)
        self.assertEqual(s.name, "HAL_Init")

    def test_find_containing(self):
        s = self.table.find_containing(0x08000120)
        self.assertIsNotNone(s)
        self.assertEqual(s.name, "main")

    def test_find_containing_out_of_range(self):
        # main is at 0x08000100, size=64, so 0x08000140 is past end
        s = self.table.find_containing(0x08000140)
        self.assertIsNone(s)

    def test_format_addr_exact(self):
        result = self.table.format_addr(0x08000100)
        self.assertIn("main", result)

    def test_format_addr_with_offset(self):
        result = self.table.format_addr(0x08000110)
        self.assertIn("main+0x10", result)

    def test_format_addr_unknown(self):
        result = self.table.format_addr(0x08008000)
        self.assertEqual(result, "0x08008000")

    def test_search(self):
        results = self.table.search("hal")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "HAL_Init")

    def test_search_no_match(self):
        results = self.table.search("xyz")
        self.assertEqual(len(results), 0)

    def test_count(self):
        self.assertEqual(self.table.count, 4)


# ── Semihosting Tests ──────────────────────────────────────────────


class SemihostingTests(unittest.TestCase):
    def setUp(self):
        self.sh = SemihostingHandler(enabled=True, _console_echo=False)

    def _mem(self, data: bytes, base: int = 0):
        """Helper: create a mem_read callable that returns data at base."""
        store = dict(enumerate(data, start=base))

        def mem_read(addr, size):
            return bytes(store.get(addr + i, 0) for i in range(size))

        def mem_write(addr, data_bytes):
            for i, b in enumerate(data_bytes):
                store[addr + i] = b

        return mem_read, mem_write

    def test_writec(self):
        mem_read, mem_write = self._mem(b"A")
        result = self.sh.handle(0x03, 0, mem_read, mem_write, None)
        self.assertEqual(result, 0)
        self.assertEqual(self.sh.output, b"A")

    def test_write0_null_terminated(self):
        mem_read, mem_write = self._mem(b"Hello\x00World")
        result = self.sh.handle(0x04, 0, mem_read, mem_write, None)
        self.assertEqual(result, 0)
        self.assertEqual(self.sh.output, b"Hello")

    def test_write_with_params(self):
        # SYS_WRITE: params at r1 = [fd(4), data_ptr(4), length(4)]
        data_str = b"Test!"
        params = (1).to_bytes(4, "little")  # fd=1 (stdout)
        params += (100).to_bytes(4, "little")  # data_ptr
        params += len(data_str).to_bytes(4, "little")  # length
        # Build memory: params at 0, data at 100
        store = {}
        for i, b in enumerate(params):
            store[i] = b
        for i, b in enumerate(data_str):
            store[100 + i] = b

        def mem_read(addr, size):
            return bytes(store.get(addr + i, 0) for i in range(size))

        def mem_write(addr, data_bytes):
            pass

        result = self.sh.handle(0x05, 0, mem_read, mem_write, None)
        self.assertEqual(result, 0)
        self.assertEqual(self.sh.output, b"Test!")

    def test_drain_output(self):
        mem_read, mem_write = self._mem(b"X")
        self.sh.handle(0x03, 0, mem_read, mem_write, None)
        data = self.sh.drain_output()
        self.assertEqual(data, b"X")
        self.assertEqual(self.sh.output, b"")

    def test_disabled(self):
        self.sh.enabled = False
        mem_read, mem_write = self._mem(b"A")
        result = self.sh.handle(0x03, 0, mem_read, mem_write, None)
        self.assertEqual(result, -1)
        self.assertEqual(self.sh.output, b"")

    def test_errno(self):
        result = self.sh.handle(0x13, 0, lambda a, s: b"", lambda a, d: None, None)
        self.assertEqual(result, 0)

    def test_open_stdout(self):
        # SYS_OPEN params: [name_ptr(4), mode(4), name_len(4)]
        name = b":tt\x00"
        params = (100).to_bytes(4, "little")  # name_ptr
        params += (0).to_bytes(4, "little")  # mode
        params += len(name).to_bytes(4, "little")  # name_len
        store = {}
        for i, b in enumerate(params):
            store[i] = b
        for i, b in enumerate(name):
            store[100 + i] = b

        def mem_read(addr, size):
            return bytes(store.get(addr + i, 0) for i in range(size))

        result = self.sh.handle(0x01, 0, mem_read, lambda a, d: None, None)
        self.assertEqual(result, 1)  # stdout handle


# ── Shell Command Tests for sym/semihost/coverage ─────────────────


class SymCommandTests(unittest.TestCase):
    def setUp(self):
        self.emu = _FakeEmu()
        # Populate symbol table
        syms = [
            Symbol("main", 0x08000100, 64, "func"),
            Symbol("HAL_Init", 0x08000200, 128, "func"),
        ]
        for s in syms:
            self.emu.symbols._by_name[s.name] = s
            self.emu.symbols._by_addr[s.address] = s
        self.emu.symbols._func_addrs = sorted(
            s.address for s in syms if s.sym_type == "func"
        )
        self.cmds = Commands(emu=self.emu, bus=_FakeBus())

    def test_sym_stats(self):
        out = self.cmds.cmd_sym(["stats"])
        self.assertIn("2", out)

    def test_sym_search(self):
        out = self.cmds.cmd_sym(["search", "hal"])
        self.assertIn("HAL_Init", out)

    def test_sym_search_no_match(self):
        out = self.cmds.cmd_sym(["search", "xyz"])
        self.assertIn("no matches", out)

    def test_sym_addr(self):
        out = self.cmds.cmd_sym(["addr", "0x08000100"])
        self.assertIn("main", out)

    def test_sym_name(self):
        out = self.cmds.cmd_sym(["name", "main"])
        self.assertIn("0x08000100", out)

    def test_sym_name_missing(self):
        out = self.cmds.cmd_sym(["name", "missing"])
        self.assertIn("not found", out)


class SemihostCommandTests(unittest.TestCase):
    def setUp(self):
        self.emu = _FakeEmu()
        self.cmds = Commands(emu=self.emu, bus=_FakeBus())

    def test_semihost_on_off(self):
        out = self.cmds.cmd_semihost(["off"])
        self.assertIn("disabled", out)
        self.assertFalse(self.emu.semihosting.enabled)
        out = self.cmds.cmd_semihost(["on"])
        self.assertIn("enabled", out)
        self.assertTrue(self.emu.semihosting.enabled)

    def test_semihost_status(self):
        out = self.cmds.cmd_semihost(["status"])
        self.assertIn("enabled=True", out)

    def test_semihost_drain_empty(self):
        out = self.cmds.cmd_semihost(["drain"])
        self.assertIn("empty", out)

    def test_semihost_drain_with_data(self):
        self.emu.semihosting._output_buffer.extend(b"Hello World")
        out = self.cmds.cmd_semihost(["drain"])
        self.assertIn("Hello World", out)
        self.assertEqual(self.emu.semihosting.output, b"")

    def test_semihost_echo_toggle(self):
        out = self.cmds.cmd_semihost(["echo", "off"])
        self.assertIn("off", out)
        self.assertFalse(self.emu.semihosting._console_echo)
        out = self.cmds.cmd_semihost(["echo", "on"])
        self.assertIn("on", out)
        self.assertTrue(self.emu.semihosting._console_echo)


class CoverageCommandTests(unittest.TestCase):
    def setUp(self):
        self.emu = _FakeEmu()
        self.cmds = Commands(emu=self.emu, bus=_FakeBus())

    def test_coverage_on_off(self):
        out = self.cmds.cmd_coverage(["on"])
        self.assertIn("enabled", out)
        self.assertTrue(self.emu.coverage_enabled)
        out = self.cmds.cmd_coverage(["off"])
        self.assertIn("disabled", out)
        self.assertFalse(self.emu.coverage_enabled)

    def test_coverage_status(self):
        self.emu._coverage = {0x08000100, 0x08000102, 0x08000104}
        out = self.cmds.cmd_coverage(["status"])
        self.assertIn("unique_pcs=3", out)

    def test_coverage_clear(self):
        self.emu._coverage = {0x08000100}
        out = self.cmds.cmd_coverage(["clear"])
        self.assertIn("cleared", out)
        self.assertEqual(len(self.emu._coverage), 0)

    def test_coverage_report_empty(self):
        out = self.cmds.cmd_coverage(["report"])
        self.assertIn("no coverage data", out)

    def test_coverage_report_with_data(self):
        self.emu._coverage = {0x08000100, 0x08000102}
        out = self.cmds.cmd_coverage(["report"])
        self.assertIn("unique PCs covered: 2", out)
        self.assertIn("0x08000100", out)

    def test_coverage_export(self):
        import tempfile
        import os
        self.emu._coverage = {0x08000100, 0x08000104, 0x08000102}
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "cov.txt")
            out = self.cmds.cmd_coverage(["export", path])
            self.assertIn("exported 3", out)
            with open(path) as f:
                contents = f.read()
            self.assertIn("0x08000100", contents)
            self.assertIn("0x08000102", contents)
            self.assertIn("0x08000104", contents)


# ── Field Decode Tests ─────────────────────────────────────────────


class FieldDecodeTests(unittest.TestCase):
    def setUp(self):
        fields = (
            SvdField("ENABLE", 0, 1),
            SvdField("TICKINT", 1, 1),
            SvdField("CLKSOURCE", 2, 1),
            SvdField("COUNTFLAG", 16, 1),
        )
        reg = SvdRegister("CTRL", offset=0x00, fields=fields)
        periph = SvdPeripheral("STK", base_address=0xE000E010, size=0x20, registers=(reg,))
        arange = AddressRange(base=0xE000E010, end=0xE000E030, peripheral=periph)
        self.amap = AddressMap(
            device_name="test",
            peripherals=(periph,),
            ranges=(arange,),
        )
        self.emu = _FakeEmu()
        self.bus = _FakeBusWithAmap(self.amap)
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_periph_read_shows_fields(self):
        out = self.cmds.cmd_periph(["read", "0xE000E010"])
        self.assertIn("ENABLE", out)
        self.assertIn("TICKINT", out)
        self.assertIn("CLKSOURCE", out)
        self.assertIn("COUNTFLAG", out)

    def test_periph_read_named(self):
        out = self.cmds.cmd_periph(["read", "STK.CTRL"])
        self.assertIn("ENABLE", out)


class _FakeBusWithAmap:
    def __init__(self, amap):
        self.amap = amap
        self._val = 0x00010007  # ENABLE=1, TICKINT=1, CLKSOURCE=1, COUNTFLAG=1

    def read(self, addr, size):
        return self._val

    def write(self, addr, size, value):
        self._val = value

    def model_for_name(self, name):
        return None


class FieldDecodeValuesTests(unittest.TestCase):
    def test_field_values_decoded_correctly(self):
        fields = (
            SvdField("LOW", 0, 4),
            SvdField("HIGH", 4, 4),
        )
        reg = SvdRegister("DR", offset=0x00, fields=fields)
        periph = SvdPeripheral("TEST", base_address=0x40000000, size=0x10, registers=(reg,))
        arange = AddressRange(base=0x40000000, end=0x40000010, peripheral=periph)
        amap = AddressMap(
            device_name="test",
            peripherals=(periph,),
            ranges=(arange,),
        )
        bus = _FakeBusWithAmap(amap)
        bus._val = 0xA5
        emu = _FakeEmu()
        cmds = Commands(emu=emu, bus=bus)
        out = cmds.cmd_periph(["read", "0x40000000"])
        # HIGH field: bits [7:4] = 0xA = 10
        self.assertIn("HIGH", out)
        self.assertIn("0xA", out)
        # LOW field: bits [3:0] = 0x5 = 5
        self.assertIn("LOW", out)
        self.assertIn("0x5", out)


if __name__ == "__main__":
    unittest.main()
