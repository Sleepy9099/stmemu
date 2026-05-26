"""Tests for the fuzzer: mutator, injector, and engine."""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from pathlib import Path

# ── Stub external dependencies ─────────────────────────────────────

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


from stmemu.fuzz.mutator import Mutator
from stmemu.fuzz.injector import Injector, InjectionTarget, FunctionTargetConfig
from stmemu.fuzz.engine import FuzzEngine, FuzzStats, CorpusEntry, FuzzFinding, IterationTrace
from stmemu.core.symbols import SymbolTable
from stmemu.core.semihosting import SemihostingHandler


# ── Fakes ──────────────────────────────────────────────────────────


class _FakeUartModel:
    def __init__(self):
        self.rx = bytearray()

    def inject_rx_bytes(self, data):
        self.rx.extend(data)

    def drain_tx_bytes(self):
        return b""

    def peek_tx_bytes(self):
        return b""

    def status_summary(self):
        return ""


class _FakeSpiModel:
    def __init__(self):
        self.rx = bytearray()

    def inject_rx(self, data):
        self.rx.extend(data)

    def drain_tx(self):
        return b""


class _FakeI2cModel:
    def __init__(self):
        self.rx = bytearray()

    def inject_rx(self, data):
        self.rx.extend(data)

    def drain_tx(self):
        return b""


class _FakeGpioModel:
    def __init__(self):
        self._BSRR = 0x18
        self._ODR = 0x14
        self._IDR = 0x10
        self._MODER = 0x00
        self._odr = 0

    def write(self, offset, size, value):
        if offset == self._BSRR:
            set_bits = value & 0xFFFF
            reset_bits = (value >> 16) & 0xFFFF
            self._odr = (self._odr | set_bits) & ~reset_bits

    def read(self, offset, size):
        if offset == self._IDR:
            return self._odr
        return 0

    def read_register_value(self, offset):
        if offset == self._ODR:
            return self._odr
        return 0


class _FakeMounted:
    def __init__(self, name, model):
        self.name = name
        self.base = 0x40000000
        self.end = 0x40000400
        self.model = model


class _FakeBus:
    def __init__(self, models=None):
        self._models = models or {}
        self._mounted = [_FakeMounted(n, m) for n, m in self._models.items()]

    def mounted_ranges(self):
        return tuple(self._mounted)

    def model_for_name(self, name):
        return self._models.get(name.upper())

    def read(self, addr, size):
        return 0

    def write(self, addr, size, value):
        pass

    def snapshot_models_state(self):
        return {}

    def restore_models_state(self, state):
        pass


class _FakeEmu:
    """Minimal emulator fake for fuzzer testing."""

    def __init__(self):
        self.symbols = SymbolTable()
        self.semihosting = SemihostingHandler()
        self.coverage_enabled = False
        self._coverage: set[int] = set()
        self._coverage_hits: dict[int, int] = {}
        self._coverage_snapshots: dict[str, set[int]] = {}
        self.flash_base = 0x08000000
        self.flash_end = 0x08010000
        self.pc = 0x08000100
        self.stuck_loop_threshold = 5000
        self._pc_hist: dict[int, int] = {}
        self._snapshots: dict[str, object] = {}
        self._run_callback = None
        self._regs = {"r0": 0, "r1": 0, "sp": 0x20001000, "lr": 0, "pc": 0x08000100}
        self._memory: dict[int, bytes] = {}
        self.last_fault_report = None
        self.last_pc_break: int | None = None
        self._breakpoints: set[int] = set()

    def save_snapshot(self, name):
        self._snapshots[name] = {
            "coverage": set(self._coverage),
            "pc": self.pc,
        }
        return types.SimpleNamespace(name=name)

    def load_snapshot(self, name):
        snap = self._snapshots.get(name)
        if snap is None:
            raise KeyError(name)
        self._pc_hist.clear()
        self.last_fault_report = None
        self.last_pc_break = None
        return types.SimpleNamespace(name=name)

    def add_breakpoint(self, addr):
        self._breakpoints.add(addr & ~1)

    def remove_breakpoint(self, addr):
        self._breakpoints.discard(addr & ~1)

    def run(self, count):
        self.last_pc_break = None
        if self._run_callback:
            self._run_callback(self, count)
        else:
            import random
            for _ in range(random.randint(0, 3)):
                pc = random.randint(0x08000100, 0x08000FFF) & ~1
                self._coverage.add(pc)
                self._coverage_hits[pc] = self._coverage_hits.get(pc, 0) + 1
        if (self.pc & ~1) in self._breakpoints:
            self.last_pc_break = self.pc & ~1

    def mem_write(self, addr, data):
        self._memory[addr] = bytes(data)

    def mem_read(self, addr, size):
        data = self._memory.get(addr, b"")
        if len(data) >= size:
            return data[:size]
        return data + b"\x00" * (size - len(data))

    def write_reg(self, name, value):
        name = name.lower()
        self._regs[name] = value & 0xFFFFFFFF
        if name == "pc":
            self.pc = value & ~1

    def read_regs(self):
        return dict(self._regs)

    def capture_fault_report(self, reason, *, detail=None):
        return {"reason": reason, "detail": detail or "", "pc": self.pc}


# ── Mutator Tests ──────────────────────────────────────────────────


class MutatorTests(unittest.TestCase):
    def test_generate_within_bounds(self):
        m = Mutator(seed=42)
        for _ in range(20):
            data = m.generate(min_len=5, max_len=10)
            self.assertTrue(5 <= len(data) <= 10)

    def test_generate_default_range(self):
        m = Mutator(seed=42)
        data = m.generate()
        self.assertTrue(1 <= len(data) <= 256)

    def test_mutate_preserves_nonzero_length(self):
        m = Mutator(seed=42)
        original = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        for _ in range(50):
            result = m.mutate(original)
            self.assertTrue(len(result) > 0)

    def test_mutate_changes_data(self):
        m = Mutator(seed=42)
        original = b"\x00" * 32
        changed = False
        for _ in range(20):
            result = m.mutate(original)
            if result != bytearray(original):
                changed = True
                break
        self.assertTrue(changed, "mutate should change data at least sometimes")

    def test_mutate_empty_generates(self):
        m = Mutator(seed=42)
        result = m.mutate(b"")
        self.assertTrue(len(result) > 0)

    def test_mutate_max_len_enforced(self):
        m = Mutator(seed=42)
        original = b"\x00" * 16
        for _ in range(100):
            result = m.mutate(original, max_mutations=4, max_len=20)
            self.assertLessEqual(len(result), 20)

    def test_splice(self):
        m = Mutator(seed=42)
        a = b"AAAA"
        b_data = b"BBBB"
        result = m.splice(a, b_data)
        self.assertTrue(len(result) > 0)

    def test_splice_empty(self):
        m = Mutator(seed=42)
        self.assertEqual(m.splice(b"", b"hello"), bytearray(b"hello"))
        self.assertEqual(m.splice(b"hello", b""), bytearray(b"hello"))

    def test_splice_max_len_enforced(self):
        m = Mutator(seed=42)
        a = b"A" * 100
        b_data = b"B" * 100
        for _ in range(50):
            result = m.splice(a, b_data, max_len=32)
            self.assertLessEqual(len(result), 32)

    def test_set_seed_reproducible(self):
        m1 = Mutator(seed=123)
        m2 = Mutator(seed=123)
        for _ in range(10):
            self.assertEqual(m1.generate(5, 20), m2.generate(5, 20))

    def test_dictionary_insert(self):
        m = Mutator(seed=42, dictionary=[b"\xDE\xAD", b"\xBE\xEF"])
        original = b"\x00" * 32
        found_dict = False
        for _ in range(100):
            result = m.mutate(original, max_mutations=1)
            if b"\xDE\xAD" in result or b"\xBE\xEF" in result:
                found_dict = True
                break
        self.assertIsInstance(result, bytearray)

    def test_add_dict_entry(self):
        m = Mutator(seed=42)
        m.add_dict_entry(b"test")
        m.add_dict_entry(b"test")  # duplicate should not be added
        self.assertEqual(len(m._dictionary), 1)


# ── Injector Tests ─────────────────────────────────────────────────


class InjectorTests(unittest.TestCase):
    def _make_bus_with_targets(self):
        from stmemu.peripherals.usart import Stm32UsartPeripheral
        from stmemu.peripherals.spi import SpiPeripheral
        from stmemu.peripherals.i2c import I2cPeripheral
        from stmemu.peripherals.gpio import GpioPeripheral

        uart = _FakeUartModel()
        spi = _FakeSpiModel()
        i2c = _FakeI2cModel()
        gpio = _FakeGpioModel()
        return uart, spi, i2c, gpio

    def test_inject_uart(self):
        uart = _FakeUartModel()
        target = InjectionTarget(name="USART1", kind="uart", model=uart)
        inj = Injector(bus=_FakeBus())
        inj.targets = [target]
        desc = inj.inject(target, b"\x01\x02\x03")
        self.assertIn("uart", desc)
        self.assertEqual(bytes(uart.rx), b"\x01\x02\x03")

    def test_inject_spi(self):
        spi = _FakeSpiModel()
        target = InjectionTarget(name="SPI1", kind="spi", model=spi)
        inj = Injector(bus=_FakeBus())
        inj.targets = [target]
        desc = inj.inject(target, b"\xAA\xBB")
        self.assertIn("spi", desc)
        self.assertEqual(bytes(spi.rx), b"\xAA\xBB")

    def test_inject_i2c(self):
        i2c = _FakeI2cModel()
        target = InjectionTarget(name="I2C1", kind="i2c", model=i2c)
        inj = Injector(bus=_FakeBus())
        inj.targets = [target]
        desc = inj.inject(target, b"\xCC\xDD")
        self.assertIn("i2c", desc)
        self.assertEqual(bytes(i2c.rx), b"\xCC\xDD")

    def test_inject_gpio(self):
        gpio = _FakeGpioModel()
        target = InjectionTarget(name="GPIOA", kind="gpio", model=gpio)
        inj = Injector(bus=_FakeBus())
        inj.targets = [target]
        desc = inj.inject(target, b"\xFF\x00")  # set pins 0-7
        self.assertIn("gpio", desc)
        self.assertEqual(gpio._odr & 0xFF, 0xFF)

    def test_inject_memory(self):
        emu = _FakeEmu()
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_memory_target("PARSE_BUF", 0x20000100, size_reg="r1")
        desc = inj.inject(target, b"\xAA\xBB\xCC")
        self.assertIn("memory", desc)
        self.assertEqual(emu.mem_read(0x20000100, 3), b"\xAA\xBB\xCC")
        self.assertEqual(emu._regs["r1"], 3)

    def test_inject_memory_no_size_reg(self):
        emu = _FakeEmu()
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_memory_target("RAW_BUF", 0x20000200)
        desc = inj.inject(target, b"\x01\x02")
        self.assertIn("memory", desc)
        self.assertEqual(emu.mem_read(0x20000200, 2), b"\x01\x02")

    def test_inject_function(self):
        emu = _FakeEmu()
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target("parse_pkt", 0x08001000, 0x20000400)
        desc = inj.inject(target, b"\xDE\xAD\xBE\xEF")
        self.assertIn("function", desc)
        self.assertEqual(emu.mem_read(0x20000400, 4), b"\xDE\xAD\xBE\xEF")
        self.assertEqual(emu._regs["r0"], 0x20000400)
        self.assertEqual(emu._regs["r1"], 4)
        self.assertEqual(emu.pc, 0x08001000)

    def test_inject_memory_no_emu(self):
        inj = Injector(bus=_FakeBus())
        target = InjectionTarget(
            name="BUF", kind="memory", model=None, address=0x20000100,
        )
        inj.targets.append(target)
        desc = inj.inject(target, b"\x01")
        self.assertIn("no emulator", desc)

    def test_inject_random_target(self):
        uart = _FakeUartModel()
        spi = _FakeSpiModel()
        inj = Injector(bus=_FakeBus())
        inj.set_seed(42)
        inj.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart),
            InjectionTarget(name="SPI1", kind="spi", model=spi),
        ]
        desc = inj.inject_random_target(b"\x01\x02")
        self.assertTrue(len(uart.rx) > 0 or len(spi.rx) > 0)

    def test_inject_all(self):
        uart = _FakeUartModel()
        spi = _FakeSpiModel()
        inj = Injector(bus=_FakeBus())
        inj.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart),
            InjectionTarget(name="SPI1", kind="spi", model=spi),
        ]
        results = inj.inject_all(b"\x01\x02\x03\x04")
        self.assertEqual(len(results), 2)
        self.assertTrue(len(uart.rx) > 0)
        self.assertTrue(len(spi.rx) > 0)

    def test_list_targets(self):
        inj = Injector(bus=_FakeBus())
        inj.targets = [
            InjectionTarget(name="USART1", kind="uart", model=None),
            InjectionTarget(name="SPI1", kind="spi", model=None),
        ]
        result = inj.list_targets()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "USART1")
        self.assertEqual(result[1]["kind"], "spi")

    def test_discover_preserves_manual_targets(self):
        emu = _FakeEmu()
        inj = Injector(bus=_FakeBus(), emu=emu)
        inj.add_memory_target("BUF", 0x20000100)
        inj.add_function_target("fn", 0x08001000, 0x20000200)
        inj.discover_targets()
        kinds = [t.kind for t in inj.targets]
        self.assertIn("memory", kinds)
        self.assertIn("function", kinds)

    def test_inject_function_ptr_len_abi(self):
        emu = _FakeEmu()
        cfg = FunctionTargetConfig(abi="ptr_len", buf_reg="r0", len_reg="r1")
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        desc = inj.inject(target, b"\xAA\xBB\xCC")
        self.assertIn("function", desc)
        self.assertIn("ptr_len", desc)
        self.assertEqual(emu._regs["r0"], 0x20000400)
        self.assertEqual(emu._regs["r1"], 3)
        self.assertEqual(emu.pc, 0x08001000)

    def test_inject_function_ptr_abi(self):
        emu = _FakeEmu()
        cfg = FunctionTargetConfig(abi="ptr", buf_reg="r2")
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target(
            "fn", 0x08002000, 0x20000800, fn_config=cfg,
        )
        desc = inj.inject(target, b"\x01\x02")
        self.assertIn("ptr", desc)
        self.assertEqual(emu._regs["r2"], 0x20000800)
        self.assertEqual(emu.mem_read(0x20000800, 2), b"\x01\x02")
        self.assertEqual(emu.pc, 0x08002000)

    def test_inject_function_regs_abi(self):
        emu = _FakeEmu()
        cfg = FunctionTargetConfig(abi="regs")
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target(
            "fn", 0x08003000, 0x20000400, fn_config=cfg,
        )
        data = b"\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00"
        desc = inj.inject(target, data)
        self.assertIn("regs", desc)
        self.assertEqual(emu._regs["r0"], 1)
        self.assertEqual(emu._regs["r1"], 2)
        self.assertEqual(emu._regs["r2"], 3)
        self.assertEqual(emu._regs["r3"], 4)
        self.assertEqual(emu.pc, 0x08003000)

    def test_inject_function_regs_abi_short_data(self):
        emu = _FakeEmu()
        cfg = FunctionTargetConfig(abi="regs")
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target(
            "fn", 0x08003000, 0x20000400, fn_config=cfg,
        )
        desc = inj.inject(target, b"\xFF\x00")
        self.assertEqual(emu._regs["r0"], 0x000000FF)

    def test_inject_function_return_stop_sets_lr(self):
        emu = _FakeEmu()
        cfg = FunctionTargetConfig(stop="return", return_addr=0x0800FFFE)
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        desc = inj.inject(target, b"\x01")
        self.assertIn("return", desc)
        self.assertEqual(emu._regs["lr"], 0x0800FFFE | 1)

    def test_function_config_validation(self):
        with self.assertRaises(ValueError):
            FunctionTargetConfig(abi="invalid")
        with self.assertRaises(ValueError):
            FunctionTargetConfig(stop="invalid")

    def test_inject_function_default_config(self):
        emu = _FakeEmu()
        inj = Injector(bus=_FakeBus(), emu=emu)
        target = inj.add_function_target("fn", 0x08001000, 0x20000400)
        self.assertIsNotNone(target.fn_config)
        self.assertEqual(target.fn_config.abi, "ptr_len")
        self.assertEqual(target.fn_config.stop, "steps")


# ── FuzzEngine Tests ───────────────────────────────────────────────


class FuzzEngineTests(unittest.TestCase):
    def _make_engine(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        uart = _FakeUartModel()
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart)
        ]
        eng._snapshot_name = "__fuzz_test"
        emu.save_snapshot("__fuzz_test")
        emu.coverage_enabled = True
        eng.stats.coverage_at_start = len(emu._coverage)
        return eng, emu, uart

    def test_run_executes_iterations(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=10, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 10)
        self.assertTrue(eng.stats.elapsed >= 0)

    def test_run_accumulates_coverage(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=20, steps_per_iter=100)
        self.assertGreater(eng.stats.coverage_current, 0)

    def test_global_coverage_tracks_novelty(self):
        eng, emu, uart = self._make_engine()
        seen_pcs = set()
        call_count = [0]

        def deterministic_run(emu_ref, count):
            call_count[0] += 1
            pc = 0x08000100 + (call_count[0] * 2)
            emu_ref._coverage.add(pc)

        emu._run_callback = deterministic_run
        eng.seed(42)
        eng.run(iterations=5, steps_per_iter=100)
        self.assertEqual(len(eng._global_coverage), 5)
        self.assertEqual(eng.stats.coverage_current, 5)
        self.assertEqual(eng.stats.new_coverage_inputs, 5)

    def test_global_coverage_no_double_counting(self):
        eng, emu, uart = self._make_engine()

        def same_pc_run(emu_ref, count):
            emu_ref._coverage.add(0x08000200)

        emu._run_callback = same_pc_run
        eng.seed(42)
        eng.run(iterations=5, steps_per_iter=100)
        self.assertEqual(len(eng._global_coverage), 1)
        self.assertEqual(eng.stats.new_coverage_inputs, 1)

    def test_corpus_grows_on_new_coverage(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=50, steps_per_iter=100)
        self.assertGreater(len(eng.corpus), 0)

    def test_crash_detection(self):
        eng, emu, uart = self._make_engine()
        crash_count = [0]

        def crashing_run(emu_ref, count):
            crash_count[0] += 1
            if crash_count[0] % 3 == 0:
                raise RuntimeError("HardFault at 0x08000200")
            import random
            pc = random.randint(0x08000100, 0x08000FFF) & ~1
            emu_ref._coverage.add(pc)

        emu._run_callback = crashing_run
        eng.seed(42)
        findings = eng.run(iterations=9, steps_per_iter=100)
        self.assertGreater(eng.stats.crashes, 0)
        crash_findings = [f for f in findings if "crash" in f.kind]
        self.assertGreater(len(crash_findings), 0)
        for cf in crash_findings:
            if cf.fault_report is not None:
                self.assertIn("reason", cf.fault_report)

    def test_seed_corpus_used_first(self):
        eng, emu, uart = self._make_engine()
        eng.add_seed_input(b"\xAA\xBB\xCC")
        eng.add_seed_input(b"\xDD\xEE\xFF")
        eng.seed(42)
        eng.run(iterations=2, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 2)

    def test_format_stats(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=5, steps_per_iter=100)
        text = eng.format_stats()
        self.assertIn("iterations:", text)
        self.assertIn("corpus size:", text)
        self.assertIn("coverage", text)

    def test_format_findings(self):
        eng, emu, uart = self._make_engine()
        eng.findings.append(FuzzFinding(
            iteration=1, kind="crash", input_data=b"\x01\x02",
            target_name="USART1", target_kind="uart",
            new_pcs=5, detail="boom",
        ))
        text = eng.format_findings()
        self.assertIn("crash", text)
        self.assertIn("USART1", text)

    def test_format_findings_empty(self):
        eng, emu, uart = self._make_engine()
        self.assertEqual(eng.format_findings(), "no findings")

    def test_export_findings(self):
        eng, emu, uart = self._make_engine()
        eng.findings.append(FuzzFinding(
            iteration=1, kind="unique_crash", input_data=b"\xDE\xAD",
            target_name="USART1", target_kind="uart",
            new_pcs=3, detail="HardFault",
            fault_report={"reason": "fuzz_crash", "pc": 0x08000200},
        ))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            count = eng.export_findings(path)
            self.assertEqual(count, 1)
            data = json.loads(path.read_text())
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["kind"], "unique_crash")
            self.assertEqual(data[0]["input_hex"], "dead")
            self.assertIn("fault_report", data[0])

    def test_export_corpus(self):
        eng, emu, uart = self._make_engine()
        eng.corpus.append(CorpusEntry(
            data=b"\x01\x02\x03", target_name="USART1",
            target_kind="uart", new_pcs=2,
            iteration_found=5, total_coverage_at_find=10,
        ))
        with tempfile.TemporaryDirectory() as td:
            outdir = Path(td) / "corpus"
            count = eng.export_corpus(outdir)
            self.assertEqual(count, 1)
            files = list(outdir.iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b"\x01\x02\x03")

    def test_import_corpus(self):
        eng, emu, uart = self._make_engine()
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "input_001.bin").write_bytes(b"\xAA\xBB")
            (Path(td) / "input_002.bin").write_bytes(b"\xCC\xDD")
            count = eng.import_corpus(Path(td))
            self.assertEqual(count, 2)
            self.assertEqual(len(eng.seed_corpus), 2)

    def test_reset(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=10, steps_per_iter=100)
        eng.reset()
        self.assertEqual(eng.stats.iterations, 0)
        self.assertEqual(len(eng.corpus), 0)
        self.assertEqual(len(eng.findings), 0)
        self.assertEqual(len(eng._global_coverage), 0)

    def test_mode_round_robin(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        uart1 = _FakeUartModel()
        uart2 = _FakeUartModel()
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart1),
            InjectionTarget(name="USART2", kind="uart", model=uart2),
        ]
        eng._snapshot_name = "__fuzz_rr"
        emu.save_snapshot("__fuzz_rr")
        emu.coverage_enabled = True
        eng.mode = "round_robin"
        eng.seed(42)
        eng.run(iterations=4, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 4)

    def test_mode_all(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        uart1 = _FakeUartModel()
        uart2 = _FakeUartModel()
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart1),
            InjectionTarget(name="USART2", kind="uart", model=uart2),
        ]
        eng._snapshot_name = "__fuzz_all"
        emu.save_snapshot("__fuzz_all")
        emu.coverage_enabled = True
        eng.mode = "all"
        eng.seed(42)
        eng.run(iterations=3, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 3)

    def test_max_input_len_enforced_during_run(self):
        eng, emu, uart = self._make_engine()
        eng.max_input_len = 16
        eng.seed(42)
        eng.add_seed_input(b"\x00" * 32)
        eng.run(iterations=20, steps_per_iter=100)
        for entry in eng.corpus:
            self.assertLessEqual(len(entry.data), 16)

    def test_function_target_in_engine(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target("parse", 0x08001000, 0x20000400)
        eng._snapshot_name = "__fuzz_fn"
        emu.save_snapshot("__fuzz_fn")
        emu.coverage_enabled = True
        eng.seed(42)
        eng.run(iterations=3, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 3)

    def test_targets_persist_across_setup(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_memory_target("BUF", 0x20000100, size_reg="r1")
        eng.injector.add_function_target("parse", 0x08001000, 0x20000400)
        self.assertEqual(len(eng.injector.targets), 2)

        result = eng.setup(snapshot_name="__persist_test")
        kinds = [t.kind for t in eng.injector.targets]
        self.assertIn("memory", kinds)
        self.assertIn("function", kinds)
        self.assertNotIn("no injectable targets", result)

    def test_setup_twice_preserves_manual_targets(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target("fn", 0x08002000, 0x20000800)
        eng.setup(snapshot_name="__s1")
        eng.setup(snapshot_name="__s2")
        kinds = [t.kind for t in eng.injector.targets]
        self.assertIn("function", kinds)

    def test_return_stop_condition(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        cfg = FunctionTargetConfig(stop="return", return_addr=0x0800FFFE)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        eng._snapshot_name = "__fuzz_ret"
        emu.save_snapshot("__fuzz_ret")
        emu.coverage_enabled = True

        def simulate_return(emu_ref, count):
            emu_ref._coverage.add(0x08001000)
            emu_ref.pc = 0x0800FFFE

        emu._run_callback = simulate_return
        eng.seed(42)
        findings = eng.run(iterations=3, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 3)
        self.assertEqual(eng.stats.hangs, 0)
        self.assertGreater(len(eng._global_coverage), 0)

    def test_pc_stop_condition(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        cfg = FunctionTargetConfig(stop="pc", stop_pc=0x08005000)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        eng._snapshot_name = "__fuzz_pc"
        emu.save_snapshot("__fuzz_pc")
        emu.coverage_enabled = True

        def simulate_reach_pc(emu_ref, count):
            emu_ref._coverage.add(0x08001000)
            emu_ref.pc = 0x08005000

        emu._run_callback = simulate_reach_pc
        eng.seed(42)
        eng.run(iterations=2, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 2)
        self.assertEqual(eng.stats.hangs, 0)

    def test_stop_bp_cleaned_up_on_crash(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        cfg = FunctionTargetConfig(stop="return", return_addr=0x0800FFFE)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        eng._snapshot_name = "__fuzz_crash"
        emu.save_snapshot("__fuzz_crash")
        emu.coverage_enabled = True

        def crash_run(emu_ref, count):
            raise RuntimeError("boom")

        emu._run_callback = crash_run
        eng.seed(42)
        eng.run(iterations=1, steps_per_iter=100)
        self.assertEqual(eng.stats.crashes, 1)
        self.assertNotIn(0x0800FFFE, emu._breakpoints)

    def test_regs_abi_in_engine(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        cfg = FunctionTargetConfig(abi="regs", stop="return", return_addr=0x0800FFFE)
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.add_function_target(
            "fn", 0x08001000, 0x20000400, fn_config=cfg,
        )
        eng._snapshot_name = "__fuzz_regs"
        emu.save_snapshot("__fuzz_regs")
        emu.coverage_enabled = True

        def simulate_return(emu_ref, count):
            emu_ref._coverage.add(0x08001002)
            emu_ref.pc = 0x0800FFFE

        emu._run_callback = simulate_return
        eng.seed(42)
        eng.run(iterations=2, steps_per_iter=100)
        self.assertEqual(eng.stats.iterations, 2)
        self.assertEqual(eng.stats.hangs, 0)

    def test_crash_finding_has_trace(self):
        eng, emu, uart = self._make_engine()
        def crash_run(emu_ref, count):
            emu_ref._coverage.add(0x08000200)
            emu_ref._pc_hist[0x08000200] = 10
            raise RuntimeError("HardFault")
        emu._run_callback = crash_run
        eng.seed(42)
        eng.run(iterations=1, steps_per_iter=100)
        self.assertEqual(len(eng.findings), 1)
        finding = eng.findings[0]
        self.assertIsNotNone(finding.trace)
        self.assertIn("pc", finding.trace.regs)
        self.assertGreater(len(finding.trace.pc_freq), 0)
        self.assertIn(0x08000200, finding.trace.new_pcs)

    def test_new_coverage_finding_has_trace(self):
        eng, emu, uart = self._make_engine()
        call_count = [0]
        def coverage_run(emu_ref, count):
            call_count[0] += 1
            emu_ref._coverage.add(0x08000100 + call_count[0] * 2)
        emu._run_callback = coverage_run
        eng.seed(42)
        eng.run(iterations=3, steps_per_iter=100)
        cov_findings = [f for f in eng.findings if f.kind == "new_coverage"]
        self.assertGreater(len(cov_findings), 0)
        for f in cov_findings:
            self.assertIsNotNone(f.trace)

    def test_trace_to_dict(self):
        trace = IterationTrace(
            regs={"r0": 1, "pc": 0x08000100},
            pc_freq=((0x08000100, 5),),
            new_pcs=(0x08000200,),
            mmio_log=(("r", 0x40004400, 4, 0x01),),
        )
        d = trace.to_dict()
        self.assertIn("regs", d)
        self.assertIn("pc_freq", d)
        self.assertIn("new_pcs", d)
        self.assertIn("mmio_log", d)
        self.assertEqual(len(d["mmio_log"]), 1)

    def test_mmio_capture(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        uart = _FakeUartModel()
        eng.injector = Injector(bus=bus, emu=emu)
        eng.injector.targets = [
            InjectionTarget(name="USART1", kind="uart", model=uart)
        ]
        eng._snapshot_name = "__fuzz_mmio"
        emu.save_snapshot("__fuzz_mmio")
        emu.coverage_enabled = True
        eng.capture_mmio = True

        def mmio_run(emu_ref, count):
            emu_ref._coverage.add(0x08000300)
            bus.read(0x40004400, 4)
            bus.write(0x40004404, 4, 0x80)

        emu._run_callback = mmio_run
        eng.seed(42)
        eng.run(iterations=1, steps_per_iter=100)
        cov_findings = [f for f in eng.findings if f.kind == "new_coverage"]
        self.assertGreater(len(cov_findings), 0)
        trace = cov_findings[0].trace
        self.assertIsNotNone(trace)
        self.assertIsNotNone(trace.mmio_log)
        self.assertGreater(len(trace.mmio_log), 0)
        kinds = [entry[0] for entry in trace.mmio_log]
        self.assertIn("r", kinds)
        self.assertIn("w", kinds)

    def test_replay_crash(self):
        eng, emu, uart = self._make_engine()
        crash_count = [0]
        def crash_run(emu_ref, count):
            crash_count[0] += 1
            emu_ref._coverage.add(0x08000200)
            emu_ref._pc_hist[0x08000200] = 5
            if crash_count[0] <= 2:
                raise RuntimeError("HardFault")
        emu._run_callback = crash_run
        eng.seed(42)
        eng.run(iterations=1, steps_per_iter=100)
        self.assertEqual(len(eng.findings), 1)

        result = eng.replay(0, steps=100)
        self.assertIn("finding_index", result)
        self.assertEqual(result["finding_index"], 0)
        self.assertTrue(result["crashed"])
        self.assertIsNotNone(result["trace"])
        self.assertIsNotNone(result["trace"].regs)

    def test_replay_format(self):
        eng, emu, uart = self._make_engine()
        def crash_run(emu_ref, count):
            emu_ref._coverage.add(0x08000200)
            raise RuntimeError("boom")
        emu._run_callback = crash_run
        eng.seed(42)
        eng.run(iterations=1, steps_per_iter=100)

        result = eng.replay(0, steps=100)
        text = eng.format_replay(result)
        self.assertIn("replay finding #0", text)
        self.assertIn("CRASH", text)
        self.assertIn("regs:", text)

    def test_replay_out_of_range(self):
        eng, emu, uart = self._make_engine()
        with self.assertRaises(IndexError):
            eng.replay(99)

    def test_replay_no_setup(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        eng.findings.append(FuzzFinding(
            iteration=1, kind="crash", input_data=b"\x01",
            target_name="X", target_kind="uart",
            new_pcs=0, detail="boom",
        ))
        with self.assertRaises(RuntimeError):
            eng.replay(0)

    def test_export_includes_trace(self):
        eng, emu, uart = self._make_engine()
        trace = IterationTrace(
            regs={"pc": 0x08000200},
            pc_freq=((0x08000200, 10),),
            new_pcs=(0x08000200,),
        )
        eng.findings.append(FuzzFinding(
            iteration=1, kind="crash", input_data=b"\xDE\xAD",
            target_name="USART1", target_kind="uart",
            new_pcs=1, detail="boom", trace=trace,
        ))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "findings.json"
            eng.export_findings(path)
            data = json.loads(path.read_text())
            self.assertIn("trace", data[0])
            self.assertIn("regs", data[0]["trace"])
            self.assertIn("pc_freq", data[0]["trace"])

    def test_findings_show_trace_tag(self):
        eng, emu, uart = self._make_engine()
        trace = IterationTrace(
            regs={"pc": 0x08000200}, pc_freq=(), new_pcs=(),
        )
        eng.findings.append(FuzzFinding(
            iteration=1, kind="crash", input_data=b"\x01",
            target_name="USART1", target_kind="uart",
            new_pcs=0, detail="boom", trace=trace,
        ))
        text = eng.format_findings()
        self.assertIn("[trace]", text)


# ── FuzzStats Tests ────────────────────────────────────────────────


class FuzzStatsTests(unittest.TestCase):
    def test_execs_per_sec(self):
        s = FuzzStats(iterations=100, elapsed=2.0)
        self.assertAlmostEqual(s.execs_per_sec(), 50.0)

    def test_execs_per_sec_zero_elapsed(self):
        s = FuzzStats(iterations=100, elapsed=0.0)
        self.assertEqual(s.execs_per_sec(), 0.0)


# ── Shell fuzz command tests ───────────────────────────────────────


class FuzzShellCommandTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        self.emu = _FakeEmu()
        self.bus = _FakeBus()
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_fuzz_usage(self):
        out = self.cmds.cmd_fuzz([])
        self.assertIn("usage:", out)

    def test_fuzz_setup(self):
        out = self.cmds.cmd_fuzz(["setup"])
        self.assertIn("fuzz setup:", out)

    def test_fuzz_config_min_len(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "min_len", "8"])
        self.assertIn("min_input_len = 8", out)

    def test_fuzz_config_mode(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "mode", "round_robin"])
        self.assertIn("mode = round_robin", out)

    def test_fuzz_config_mode_all(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "mode", "all"])
        self.assertIn("mode = all", out)

    def test_fuzz_config_invalid_mode(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "mode", "invalid"])
        self.assertIn("must be", out)

    def test_fuzz_config_unknown_key(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "bogus", "1"])
        self.assertIn("unknown config key", out)

    def test_fuzz_stats(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["stats"])
        self.assertIn("iterations:", out)

    def test_fuzz_findings_empty(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["findings"])
        self.assertIn("no findings", out)

    def test_fuzz_corpus_empty(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["corpus"])
        self.assertIn("empty corpus", out)

    def test_fuzz_reset(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["reset"])
        self.assertIn("reset", out)

    def test_fuzz_seed(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["seed", "AABBCC"])
        self.assertIn("added seed input", out)
        self.assertIn("3 bytes", out)

    def test_fuzz_dict(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["dict", "DEADBEEF"])
        self.assertIn("added dictionary token", out)

    def test_fuzz_dict_invalid_hex(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["dict", "not_hex"])
        self.assertIn("invalid hex", out)

    def test_fuzz_run_no_setup(self):
        out = self.cmds.cmd_fuzz(["run", "10"])
        self.assertIn("fuzz setup", out)

    def test_fuzz_targets_no_setup(self):
        out = self.cmds.cmd_fuzz(["targets"])
        self.assertIn("not set up", out)

    def test_fuzz_export_findings(self):
        self.cmds.cmd_fuzz(["setup"])
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "findings.json")
            out = self.cmds.cmd_fuzz(["export", "findings", path])
            self.assertIn("exported", out)

    def test_fuzz_import_invalid_dir(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["import", "/nonexistent/dir"])
        self.assertIn("not a directory", out)

    def test_fuzz_target_memory(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["target", "memory", "PARSE_BUF", "0x20000100", "r1"])
        self.assertIn("memory target", out)
        self.assertIn("PARSE_BUF", out)

    def test_fuzz_target_function(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["target", "function", "parse_pkt", "0x08001000", "0x20000400"])
        self.assertIn("function target", out)
        self.assertIn("parse_pkt", out)

    def test_fuzz_target_usage(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["target"])
        self.assertIn("usage:", out)

    def test_fuzz_target_invalid_kind(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["target", "invalid", "x", "0x0"])
        self.assertIn("usage:", out)

    def test_fuzz_target_before_setup_persists(self):
        self.cmds.cmd_fuzz(["target", "function", "parse", "0x08001000", "0x20000400"])
        self.cmds.cmd_fuzz(["target", "memory", "BUF", "0x20000100"])
        out = self.cmds.cmd_fuzz(["setup"])
        self.assertIn("fuzz setup:", out)
        targets_out = self.cmds.cmd_fuzz(["targets"])
        self.assertIn("function", targets_out)
        self.assertIn("memory", targets_out)
        self.assertIn("parse", targets_out)
        self.assertIn("BUF", targets_out)

    def test_fuzz_target_function_with_abi(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "abi=regs",
        ])
        self.assertIn("abi=regs", out)

    def test_fuzz_target_function_with_return_stop(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "stop=return", "return_addr=0x0800FFFE",
        ])
        self.assertIn("stop=return", out)
        self.assertIn("return_addr=0x0800FFFE", out)

    def test_fuzz_target_function_with_pc_stop(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "stop=pc", "stop_pc=0x08005000",
        ])
        self.assertIn("stop=pc", out)
        self.assertIn("stop_pc=0x08005000", out)

    def test_fuzz_target_function_with_custom_regs(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "abi=ptr", "buf_reg=r2",
        ])
        self.assertIn("abi=ptr", out)

    def test_fuzz_target_function_invalid_abi(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "abi=invalid",
        ])
        self.assertIn("error:", out)

    def test_fuzz_target_function_invalid_kv(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz([
            "target", "function", "fn", "0x08001000", "0x20000400",
            "notakeyvalue",
        ])
        self.assertIn("expected key=value", out)

    def test_fuzz_replay_no_findings(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["replay", "0"])
        self.assertIn("error:", out)

    def test_fuzz_replay_no_setup(self):
        out = self.cmds.cmd_fuzz(["replay", "0"])
        self.assertIn("error:", out)

    def test_fuzz_config_capture_mmio(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "capture_mmio", "on"])
        self.assertIn("capture_mmio = on", out)
        out = self.cmds.cmd_fuzz(["config", "capture_mmio", "off"])
        self.assertIn("capture_mmio = off", out)

    def test_fuzz_replay_usage(self):
        out = self.cmds.cmd_fuzz(["replay"])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
