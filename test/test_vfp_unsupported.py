"""Unsupported VFP/FP instruction handling: countable, traceable, mode-aware.

Unicorn MCLASS builds reject many FP ops. The emulator treats them as NOPs so
firmware can boot ("permissive"), but the occurrence is now counted and emitted
as an `unsupported_fp_instruction` event, and a "strict" mode faults instead.
"""
from __future__ import annotations

import sys
import unittest
from types import SimpleNamespace

from stmemu.core.loader import FirmwareSegment
from stmemu.peripherals.bus import PeripheralBus
from stmemu.svd.address_map import AddressMap


FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000

# A 32-bit Thumb VFP instruction: bytes 30 EE 00 0A -> hw1=0xEE30 (FP coproc
# prefix 0xEExx), hw2=0x0A00. The invalid-insn hook keys on the prefix.
_VFP_INSN = bytes([0x30, 0xEE, 0x00, 0x0A, 0xFE, 0xE7])


def _load_real_emulator_class():
    for name in (
        "stmemu.core.emulator", "stmemu.core.disasm",
        "unicorn.arm_const", "unicorn.unicorn_const", "unicorn", "capstone",
    ):
        sys.modules.pop(name, None)
    from stmemu.core.emulator import Emulator
    return Emulator


def _make_emulator(program: bytes):
    Emulator = _load_real_emulator_class()
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    bus = PeripheralBus(amap)
    return Emulator(
        bus=bus,
        flash_base=FLASH_BASE,
        firmware_segments=(FirmwareSegment(address=FLASH_BASE, data=program),),
        sram_base=SRAM_BASE,
        sram_size=SRAM_SIZE,
    )


class VfpUnsupportedTests(unittest.TestCase):
    def test_permissive_counts_traces_and_nops(self):
        emu = _make_emulator(_VFP_INSN)
        events = []
        emu.bus.subscribe("unsupported_fp_instruction", lambda e: events.append(e))
        emu.write_reg("pc", FLASH_BASE | 1)

        handled = emu._hook_insn_invalid(emu.uc, None)

        self.assertTrue(handled, "permissive mode NOPs the FP instruction")
        self.assertEqual(emu.unsupported_fp_count, 1)
        self.assertEqual(emu.last_unsupported_fp_pc, FLASH_BASE)
        self.assertEqual(emu.pc & ~1, FLASH_BASE + 4, "PC advances past 32-bit insn")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "unsupported_fp_instruction")
        self.assertEqual(events[0].payload["pc"], FLASH_BASE)

    def test_strict_mode_faults(self):
        emu = _make_emulator(_VFP_INSN)
        emu.unsupported_fp_mode = "strict"
        emu.write_reg("pc", FLASH_BASE | 1)

        handled = emu._hook_insn_invalid(emu.uc, None)

        self.assertFalse(handled, "strict mode lets the FP instruction fault")
        self.assertEqual(emu.unsupported_fp_count, 1)
        self.assertIsNotNone(emu.last_fault_report)


class CpuFpCommandTests(unittest.TestCase):
    def _cmds(self, emu):
        from stmemu.shell.commands import Commands
        return Commands(emu=emu, bus=None)

    def _emu(self):
        return SimpleNamespace(
            unsupported_fp_count=2,
            unsupported_fp_mode="permissive",
            last_unsupported_fp_pc=0x08001234,
        )

    def test_count_reports_state(self):
        out = self._cmds(self._emu()).cmd_cpu(["unsupported-fp-nop", "count"])
        self.assertIn("count: 2", out)
        self.assertIn("permissive", out)
        self.assertIn("0x08001234", out)

    def test_mode_set_and_get(self):
        emu = self._emu()
        cmds = self._cmds(emu)
        self.assertIn("strict", cmds.cmd_cpu(["unsupported-fp-nop", "mode", "strict"]))
        self.assertEqual(emu.unsupported_fp_mode, "strict")
        self.assertIn("strict", cmds.cmd_cpu(["unsupported-fp-nop", "mode"]))

    def test_mode_rejects_invalid(self):
        out = self._cmds(self._emu()).cmd_cpu(["unsupported-fp-nop", "mode", "bogus"])
        self.assertIn("permissive", out.lower())

    def test_reset(self):
        emu = self._emu()
        self._cmds(emu).cmd_cpu(["unsupported-fp-nop", "reset"])
        self.assertEqual(emu.unsupported_fp_count, 0)
        self.assertIsNone(emu.last_unsupported_fp_pc)


if __name__ == "__main__":
    unittest.main()
