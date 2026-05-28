from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

from stmemu.core.loader import load_firmware
from stmemu.core.symbols import load_symbols
from stmemu.peripherals.factory import build_default_bus
from stmemu.svd.address_map import build_address_map
from stmemu.svd.svd_loader import load_svd


_DEFAULT_H743_SVD = (
    Path(__file__).resolve().parents[1]
    / "cmsis-svd-stm32"
    / "stm32h7"
    / "STM32H743.svd"
)


class Pixhawk6CBootloaderSmokeTests(unittest.TestCase):
    @staticmethod
    def _load_real_emulator_class():
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

    def test_pixhawk6c_bootloader_reaches_idle_thread_with_h743_svd(self) -> None:
        svd_path = Path(os.environ.get("STMEMU_STM32H743_SVD", _DEFAULT_H743_SVD))
        if not svd_path.exists():
            self.skipTest(f"STM32H743 SVD not found: {svd_path}")

        Emulator = self._load_real_emulator_class()
        image_path = Path(__file__).with_name("Pixhawk6C_bl.elf")
        firmware = load_firmware(image_path)
        device = load_svd(svd_path)
        bus, core = build_default_bus(build_address_map(device), firmware.vector_base)
        emu = Emulator(
            bus=bus,
            flash_base=firmware.vector_base,
            firmware_segments=firmware.segments,
            sram_base=0x20000000,
            sram_size=0x80000,
            firmware_format=firmware.format,
            firmware_entry_point=firmware.entry_point,
            core_peripheral=core,
        )

        emu.boot_from_vector_table()
        emu.run(250000)

        symbols = load_symbols(image_path)
        self.assertEqual(symbols.format_addr(emu.pc), "0x080039DC <__idle_thread>")
        self.assertIsNone(emu.last_fault_report)


if __name__ == "__main__":
    unittest.main()
