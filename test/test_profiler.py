"""Tests for the built-in execution profile report (stmemu.core.profiler)."""
from __future__ import annotations

import sys
import unittest

from stmemu.core.loader import FirmwareSegment
from stmemu.peripherals.bus import PeripheralBus
from stmemu.svd.address_map import AddressMap

FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000
# movs r0,#1 ; movs r1,#2 ; movs r2,#3 ; b .  (3 real instrs then self-branch)
_PROGRAM = bytes([0x01, 0x20, 0x02, 0x21, 0x03, 0x22, 0xFE, 0xE7])


def _load_real_emulator_class():
    for name in (
        "stmemu.core.emulator", "stmemu.core.disasm",
        "unicorn.arm_const", "unicorn.unicorn_const", "unicorn", "capstone",
    ):
        sys.modules.pop(name, None)
    from stmemu.core.emulator import Emulator
    return Emulator


def _make_emu():
    Emulator = _load_real_emulator_class()
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    bus = PeripheralBus(amap)
    emu = Emulator(
        bus=bus, flash_base=FLASH_BASE,
        firmware_segments=(FirmwareSegment(address=FLASH_BASE, data=_PROGRAM),),
        sram_base=SRAM_BASE, sram_size=SRAM_SIZE,
    )
    emu.write_reg("pc", FLASH_BASE | 1)
    emu.write_reg("sp", SRAM_BASE + 0x10000)
    emu.tick_scale = 1
    return emu


class ProfilerTest(unittest.TestCase):
    def test_report_counts_window(self):
        from stmemu.core.profiler import ProfileReport
        emu = _make_emu()
        emu.reset_profile()
        emu.step(3)                       # the 3 movs
        rep = emu.profile_report(as_text=False)
        self.assertIsInstance(rep, ProfileReport)
        self.assertEqual(rep.instructions, 3)
        self.assertAlmostEqual(rep.emulated_seconds, 3 / emu.time.cycle_hz, places=9)
        self.assertGreaterEqual(rep.wall_seconds, 0.0)
        self.assertGreaterEqual(rep.accel_factor, 0.0)

    def test_reset_zeroes_baseline(self):
        emu = _make_emu()
        emu.step(3)
        emu.reset_profile()               # baseline now at 3 instructions
        rep = emu.profile_report(as_text=False)
        self.assertEqual(rep.instructions, 0)         # nothing since reset
        self.assertEqual(rep.emulated_seconds, 0.0)

    def test_instr_per_sec_from_wall(self):
        emu = _make_emu()
        emu.reset_profile()
        emu.step(3)
        rep = emu.profile_report(as_text=False)
        if rep.wall_seconds > 0:
            self.assertAlmostEqual(rep.instr_per_sec, rep.instructions / rep.wall_seconds, places=3)

    def test_text_render(self):
        emu = _make_emu()
        emu.reset_profile()
        emu.step(3)
        txt = emu.profile_report()
        self.assertIn("profile", txt)
        self.assertIn("instructions", txt)
        self.assertIn("instr/sec", txt)


if __name__ == "__main__":
    unittest.main()
