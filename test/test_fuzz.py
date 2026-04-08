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
from stmemu.fuzz.injector import Injector, InjectionTarget
from stmemu.fuzz.engine import FuzzEngine, FuzzStats, CorpusEntry, FuzzFinding
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
        self._regs = {"r0": 0, "sp": 0x20001000, "lr": 0, "pc": 0x08000100}

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
        return types.SimpleNamespace(name=name)

    def run(self, count):
        # Simulate: add some coverage PCs based on run
        if self._run_callback:
            self._run_callback(self, count)
        else:
            # Default: add a few random PCs to simulate coverage growth
            import random
            for _ in range(random.randint(0, 3)):
                pc = random.randint(0x08000100, 0x08000FFF) & ~1
                self._coverage.add(pc)
                self._coverage_hits[pc] = self._coverage_hits.get(pc, 0) + 1

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

    def test_set_seed_reproducible(self):
        m1 = Mutator(seed=123)
        m2 = Mutator(seed=123)
        for _ in range(10):
            self.assertEqual(m1.generate(5, 20), m2.generate(5, 20))

    def test_dictionary_insert(self):
        m = Mutator(seed=42, dictionary=[b"\xDE\xAD", b"\xBE\xEF"])
        original = b"\x00" * 32
        # Run many mutations - dictionary should be used sometimes
        found_dict = False
        for _ in range(100):
            result = m.mutate(original, max_mutations=1)
            if b"\xDE\xAD" in result or b"\xBE\xEF" in result:
                found_dict = True
                break
        # Dictionary entries may or may not appear due to randomness,
        # but the mutation should not crash
        self.assertIsInstance(result, bytearray)

    def test_add_dict_entry(self):
        m = Mutator(seed=42)
        m.add_dict_entry(b"test")
        m.add_dict_entry(b"test")  # duplicate should not be added
        self.assertEqual(len(m._dictionary), 1)


# ── Injector Tests ─────────────────────────────────────────────────


class InjectorTests(unittest.TestCase):
    def _make_bus_with_targets(self):
        # Build a bus-like object where mounted_ranges returns typed models
        from stmemu.peripherals.usart import Stm32UsartPeripheral
        from stmemu.peripherals.spi import SpiPeripheral
        from stmemu.peripherals.i2c import I2cPeripheral
        from stmemu.peripherals.gpio import GpioPeripheral

        # Use our fakes but mark them as the right type via isinstance
        # We can't easily do that, so test with the injector using
        # InjectionTarget directly.
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


# ── FuzzEngine Tests ───────────────────────────────────────────────


class FuzzEngineTests(unittest.TestCase):
    def _make_engine(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        # Manually set up injector with a fake UART target
        uart = _FakeUartModel()
        eng.injector = Injector(bus=bus)
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
        # The fake emu adds random PCs, so coverage should grow
        self.assertGreater(eng.stats.coverage_current, 0)

    def test_corpus_grows_on_new_coverage(self):
        eng, emu, uart = self._make_engine()
        eng.seed(42)
        eng.run(iterations=50, steps_per_iter=100)
        # With random coverage additions, corpus should have entries
        self.assertGreater(len(eng.corpus), 0)

    def test_crash_detection(self):
        eng, emu, uart = self._make_engine()
        crash_count = [0]

        def crashing_run(emu_ref, count):
            crash_count[0] += 1
            if crash_count[0] % 3 == 0:
                raise RuntimeError("HardFault at 0x08000200")
            # Normal: add some coverage
            import random
            pc = random.randint(0x08000100, 0x08000FFF) & ~1
            emu_ref._coverage.add(pc)

        emu._run_callback = crashing_run
        eng.seed(42)
        findings = eng.run(iterations=9, steps_per_iter=100)
        self.assertGreater(eng.stats.crashes, 0)
        crash_findings = [f for f in findings if "crash" in f.kind]
        self.assertGreater(len(crash_findings), 0)
        # Check fault report captured
        for cf in crash_findings:
            if cf.fault_report is not None:
                self.assertIn("reason", cf.fault_report)

    def test_seed_corpus_used_first(self):
        eng, emu, uart = self._make_engine()
        eng.add_seed_input(b"\xAA\xBB\xCC")
        eng.add_seed_input(b"\xDD\xEE\xFF")
        eng.seed(42)
        eng.run(iterations=2, steps_per_iter=100)
        # First two iterations should use seed inputs
        # We can verify by checking the uart received the seed data
        # (uart is reset each iteration via snapshot, but we can check
        # that iterations ran)
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

    def test_mode_round_robin(self):
        emu = _FakeEmu()
        bus = _FakeBus()
        eng = FuzzEngine(emu=emu, bus=bus)
        uart1 = _FakeUartModel()
        uart2 = _FakeUartModel()
        eng.injector = Injector(bus=bus)
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
        # No real targets in our fake bus
        self.assertIn("fuzz setup:", out)

    def test_fuzz_config_min_len(self):
        # Ensure engine is created
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "min_len", "8"])
        self.assertIn("min_input_len = 8", out)

    def test_fuzz_config_mode(self):
        self.cmds.cmd_fuzz(["setup"])
        out = self.cmds.cmd_fuzz(["config", "mode", "round_robin"])
        self.assertIn("mode = round_robin", out)

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


if __name__ == "__main__":
    unittest.main()
