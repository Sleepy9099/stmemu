"""Tests for snapshot_at() + the snapshot registry metadata (C1)."""
from __future__ import annotations

import sys
import unittest

from stmemu.core.loader import FirmwareSegment
from stmemu.peripherals.bus import PeripheralBus
from stmemu.svd.address_map import AddressMap

FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000
# movs r0,#1 ; movs r1,#2 ; movs r2,#3 ; b .   (PCs: +0, +2, +4, +6)
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
        stuck_loop_auto=False,
    )
    emu.write_reg("pc", FLASH_BASE | 1)
    emu.write_reg("sp", SRAM_BASE + 0x10000)
    emu.tick_scale = 1
    return emu


class SnapshotRegistryTest(unittest.TestCase):
    def test_snapshot_at_reaches_and_records(self):
        emu = _make_emu()
        emu.snapshot_at("at_mov3", FLASH_BASE + 4)   # run to the 3rd mov
        self.assertIn("at_mov3", emu.list_snapshots())
        info = emu.snapshot_info("at_mov3")
        self.assertEqual(info["pc"], FLASH_BASE + 4)   # stopped exactly at the target
        self.assertGreaterEqual(info["instructions"], 2)  # >= the two movs reached
        self.assertIn("0x08000004", info["label"])   # default label is the addr

    def test_save_snapshot_label_and_registry(self):
        emu = _make_emu()
        emu.step(1)
        emu.save_snapshot("boot", label="post-reset")
        info = emu.snapshot_info("boot")
        self.assertEqual(info["label"], "post-reset")
        self.assertEqual(info["instructions"], 1)
        txt = emu.snapshot_registry()
        self.assertIn("snapshots", txt)
        self.assertIn("boot", txt)
        self.assertIn("post-reset", txt)

    def test_registry_resolver_annotates_pc(self):
        emu = _make_emu()
        emu.step(1)
        emu.save_snapshot("boot")
        txt = emu.snapshot_registry(resolver=lambda a: "sym_here")
        self.assertIn("sym_here", txt)

    def test_snapshot_at_unreachable_raises(self):
        emu = _make_emu()
        with self.assertRaises(RuntimeError):
            emu.snapshot_at("nope", FLASH_BASE + 0x40, max_instructions=200)
        self.assertNotIn("nope", emu.list_snapshots())

    def test_snapshot_at_leaves_no_stray_breakpoint(self):
        emu = _make_emu()
        emu.snapshot_at("at_mov3", FLASH_BASE + 4)
        self.assertNotIn(FLASH_BASE + 4, emu.list_breakpoints())


if __name__ == "__main__":
    unittest.main()
