from __future__ import annotations

import unittest
import sys

from stmemu.core.loader import FirmwareSegment
from stmemu.peripherals.bus import PeripheralBus
from stmemu.svd.address_map import AddressMap


class EmulatorMemoryMappingTests(unittest.TestCase):
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

    def test_erased_flash_is_readable_beyond_loaded_segments(self) -> None:
        Emulator = self._load_real_emulator_class()
        bus = PeripheralBus(AddressMap(device_name="TEST", peripherals=(), ranges=()))
        emu = Emulator(
            bus=bus,
            flash_base=0x08000000,
            firmware_segments=(
                FirmwareSegment(
                    address=0x08000000,
                    data=bytes.fromhex("00100020 01000008"),
                ),
            ),
            sram_base=0x20000000,
            sram_size=0x1000,
        )

        self.assertEqual(emu.mem_read(0x08001000, 4), b"\xFF" * 4)
        self.assertEqual(emu.mem_read(0x081FFFFC, 4), b"\xFF" * 4)


if __name__ == "__main__":
    unittest.main()
