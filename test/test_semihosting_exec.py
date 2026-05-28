"""End-to-end semihosting tests that exercise the BKPT 0xAB intercept through
the real Unicorn single-step loop (not just SemihostingHandler in isolation).

Regression coverage for the bug where the semihosting code-hook handled the
call but never advanced PC past the BKPT, so the instruction then raised
UC_ERR_EXCEPTION and faulted the run after the first call.
"""

from __future__ import annotations

import sys
import unittest

from stmemu.core.loader import FirmwareSegment
from stmemu.peripherals.bus import PeripheralBus
from stmemu.svd.address_map import AddressMap


FLASH_BASE = 0x08000000
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000
CHAR_OFFSET = 0x100


def _load_real_emulator_class():
    # Other test modules stub out unicorn/capstone/emulator in sys.modules when
    # those modules haven't been imported yet. Pop the stubs and re-import the
    # real classes so this test runs against real Unicorn execution regardless
    # of discovery order (mirrors test_pixhawk6c_bl.py).
    for name in (
        "stmemu.core.emulator",
        "stmemu.core.disasm",
        "unicorn.arm_const",
        "unicorn.unicorn_const",
        "unicorn",
        "capstone",
    ):
        sys.modules.pop(name, None)
    from stmemu.core.emulator import Emulator

    return Emulator


def _make_emulator(program: bytes):
    Emulator = _load_real_emulator_class()
    amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
    bus = PeripheralBus(amap)
    emu = Emulator(
        bus=bus,
        flash_base=FLASH_BASE,
        firmware_segments=(FirmwareSegment(address=FLASH_BASE, data=program),),
        sram_base=SRAM_BASE,
        sram_size=SRAM_SIZE,
    )
    emu.semihosting._console_echo = False
    return emu


class SemihostingExecTests(unittest.TestCase):
    def test_writec_loop_does_not_fault_and_emits(self) -> None:
        # Two SYS_WRITEC calls, each writing the byte R1 points at, then a
        # self-branch. If the BKPT is not stepped over, the run faults after
        # the first call and only one byte (or none) is emitted.
        program = bytes.fromhex(
            "0320"  # movs r0, #3       ; SYS_WRITEC
            "abbe"  # bkpt 0xab
            "0320"  # movs r0, #3       ; SYS_WRITEC
            "abbe"  # bkpt 0xab
            "fee7"  # b .               ; self loop
        )
        emu = _make_emulator(program)
        emu.mem_write(FLASH_BASE + CHAR_OFFSET, b"Z")
        emu.write_reg("pc", FLASH_BASE | 1)
        emu.write_reg("sp", SRAM_BASE + 0x10000)
        emu.write_reg("r1", FLASH_BASE + CHAR_OFFSET)

        emu.run(20)

        self.assertIsNone(emu.last_fault_report, "semihosting BKPT must not fault")
        self.assertEqual(emu.semihosting.output, b"ZZ")
        # PC should have advanced to the self-branch (past both BKPTs).
        self.assertEqual(emu.pc & ~1, FLASH_BASE + 0x08)

    def test_write0_string_emitted(self) -> None:
        # SYS_WRITE0 (op 0x04): R1 -> null-terminated string.
        program = bytes.fromhex(
            "0420"  # movs r0, #4       ; SYS_WRITE0
            "abbe"  # bkpt 0xab
            "fee7"  # b .               ; self loop
        )
        emu = _make_emulator(program)
        emu.mem_write(FLASH_BASE + CHAR_OFFSET, b"hello\x00")
        emu.write_reg("pc", FLASH_BASE | 1)
        emu.write_reg("sp", SRAM_BASE + 0x10000)
        emu.write_reg("r1", FLASH_BASE + CHAR_OFFSET)

        emu.run(10)

        self.assertIsNone(emu.last_fault_report)
        self.assertEqual(emu.semihosting.output, b"hello")

    def test_disabled_semihosting_still_faults_on_bkpt(self) -> None:
        # With semihosting disabled the BKPT is a genuine fault, not silently
        # stepped over. Confirms the intercept only fires when enabled.
        program = bytes.fromhex(
            "0320"  # movs r0, #3
            "abbe"  # bkpt 0xab
            "fee7"  # b .
        )
        emu = _make_emulator(program)
        emu.semihosting.enabled = False
        emu.write_reg("pc", FLASH_BASE | 1)
        emu.write_reg("sp", SRAM_BASE + 0x10000)

        with self.assertRaises(Exception):
            emu.run(10)


if __name__ == "__main__":
    unittest.main()
