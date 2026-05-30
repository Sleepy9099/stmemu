"""Unit tests for the stall analyzer (pure analysis, no Unicorn needed)."""
from __future__ import annotations

import struct
import sys
import unittest
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.core.stall_analyzer import analyze_stall  # noqa: E402


# ── duck-typed fakes standing in for the emulator + bus ────────────────

class _FakeModel:
    def __init__(self, regs):
        self._regs = regs

    def describe(self, offset):
        return self._regs.get(offset)


class _FakeMount:
    def __init__(self, name, base, end, model):
        self.name = name
        self.base = base
        self.end = end
        self.model = model


class _FakeBus:
    def __init__(self, mounts):
        self._mounts = mounts

    def _mount_for_addr(self, addr):
        for m in self._mounts:
            if m.base <= addr < m.end:
                return m
        return None


class _FakeSeg:
    def __init__(self, address, size):
        self.address = address
        self.data = b"\x00" * size


class _FakeEmu:
    def __init__(self, *, pc, mmio_ring, pc_hist, bus, stack_base, stack_words):
        self.pc = pc
        self.flash_base = 0x08000000
        self.firmware_segments = (_FakeSeg(0x08000000, 0x00200000),)
        self._mmio_ring = mmio_ring
        self._pc_hist = pc_hist
        self.bus = bus
        self.sp = stack_base
        self._stack_base = stack_base
        self._stack = b"".join(struct.pack("<I", w) for w in stack_words)

    def _active_stack_is_psp(self):
        return True

    def _read_stack_pointer(self, use_psp):
        return self._stack_base

    def mem_read(self, addr, size):
        off = addr - self._stack_base
        return self._stack[off:off + size]


class StallAnalyzerTest(unittest.TestCase):
    def _i2c_bus(self):
        model = _FakeModel({0x00: "CR1", 0x18: "ISR"})
        mount = _FakeMount("I2C4", 0x40005C00, 0x40006000, model)
        return _FakeBus([mount])

    def test_mmio_spin_loop_identified(self):
        # 60 reads of I2C4.ISR (0x40005C18), always 0 -> a stuck poll.
        isr = 0x40005C18
        ring = deque(((0x08001234, "r", isr, 4, 0x0) for _ in range(60)), maxlen=512)
        # a couple of code return addresses buried in the stack
        words = [0x00000000, 0x24001FFF, 0x08001ABD, 0x00000000, 0x08020F0D]
        emu = _FakeEmu(
            pc=0x08001234,
            mmio_ring=ring,
            pc_hist={0x08001234: 50000, 0x08001230: 49000},
            bus=self._i2c_bus(),
            stack_base=0x24001000,
            stack_words=words,
        )
        report = analyze_stall(emu)

        # Top hotspot is the polled ISR, stuck on a single value.
        self.assertTrue(report.mmio_hotspots, "expected an MMIO hotspot")
        top = report.mmio_hotspots[0]
        self.assertEqual(top.name, "I2C4.ISR")
        self.assertEqual(top.address, isr)
        self.assertEqual(top.access, "r")
        self.assertEqual(top.count, 60)
        self.assertEqual(top.distinct_values, 1)

        # Verdict names the register and flags the never-changing value.
        self.assertIn("I2C4.ISR", report.verdict)
        self.assertIn("never changes", report.verdict)

        # Backtrace recovered the two thumb code pointers (bit0 stripped).
        codes = [c for _sp, c in report.backtrace]
        self.assertIn(0x08001ABC, codes)
        self.assertIn(0x08020F0C, codes)

        text = report.format()
        self.assertIn("stall analysis", text)
        self.assertIn("0x08001234", text)

    def test_algorithmic_loop_no_dominant_mmio(self):
        # Reads of a DR with many different values (data streaming), not a
        # stuck bit -> should read as a non-converging algorithmic loop.
        model = _FakeModel({0x0C: "DR"})
        mount = _FakeMount("SPI1", 0x40013000, 0x40013400, model)
        bus = _FakeBus([mount])
        dr = 0x4001300C
        ring = deque(((0x08051000, "r", dr, 1, v & 0xFF) for v in range(80)), maxlen=512)
        emu = _FakeEmu(
            pc=0x08062217,
            mmio_ring=ring,
            pc_hist={0x08062217: 4000},
            bus=bus,
            stack_base=0x24002000,
            stack_words=[0x08062218, 0x0806280C],
        )
        report = analyze_stall(emu)
        top = report.mmio_hotspots[0]
        self.assertEqual(top.name, "SPI1.DR")
        self.assertGreater(top.distinct_values, 1)  # data, not a stuck bit
        self.assertIn("not a stuck-bit poll", report.verdict)

    def test_no_mmio_window(self):
        emu = _FakeEmu(
            pc=0x0800AAAA,
            mmio_ring=deque(maxlen=512),
            pc_hist={0x0800AAAA: 1000},
            bus=self._i2c_bus(),
            stack_base=0x24003000,
            stack_words=[0, 0, 0],
        )
        report = analyze_stall(emu)
        self.assertEqual(report.mmio_hotspots, [])
        self.assertIn("no MMIO", report.verdict)
        self.assertIn("none", report.format())


if __name__ == "__main__":
    unittest.main()
