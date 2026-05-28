"""Regression test: board-config register writes honor the register width.

_apply_register previously always issued model.write(offset, 4, val) regardless
of the register's declared size, so applying an 8- or 16-bit register value was
written as 32 bits — spilling into adjacent registers or being rejected.
"""

from __future__ import annotations

import unittest

from stmemu.board_config import _apply_register
from stmemu.svd.model import SvdPeripheral, SvdRegister


class _RecordingModel:
    def __init__(self, peripheral: SvdPeripheral) -> None:
        self.peripheral = peripheral
        self.writes: list[tuple[int, int, int]] = []

    def write(self, offset: int, size: int, value: int) -> None:
        self.writes.append((offset, size, value))


class _FakeBus:
    def __init__(self, name: str, model: _RecordingModel) -> None:
        self._models = {name.upper(): model}

    def model_for_name(self, name: str):
        return self._models.get(str(name).upper())


def _bus_with_registers() -> tuple[_FakeBus, _RecordingModel]:
    peripheral = SvdPeripheral(
        name="TST",
        base_address=0x40000000,
        size=0x400,
        registers=(
            SvdRegister(name="CR1", offset=0x00, size_bits=32),
            SvdRegister(name="BRR", offset=0x08, size_bits=16),
            SvdRegister(name="GTPR", offset=0x10, size_bits=8),
        ),
    )
    model = _RecordingModel(peripheral)
    return _FakeBus("TST", model), model


class RegisterWidthTests(unittest.TestCase):
    def test_32bit_register_writes_4_bytes(self) -> None:
        bus, model = _bus_with_registers()
        _apply_register(
            {"peripheral": "TST", "register": "CR1", "value": "0x11223344"}, bus, None
        )
        self.assertEqual(model.writes, [(0x00, 4, 0x11223344)])

    def test_16bit_register_writes_2_bytes(self) -> None:
        bus, model = _bus_with_registers()
        _apply_register(
            {"peripheral": "TST", "register": "BRR", "value": "0x1234"}, bus, None
        )
        self.assertEqual(model.writes, [(0x08, 2, 0x1234)])

    def test_8bit_register_writes_1_byte(self) -> None:
        bus, model = _bus_with_registers()
        _apply_register(
            {"peripheral": "TST", "register": "GTPR", "value": "0xAB"}, bus, None
        )
        self.assertEqual(model.writes, [(0x10, 1, 0xAB)])

    def test_raw_offset_defaults_to_4_bytes(self) -> None:
        # When the register is given as a raw numeric offset (no name match),
        # the width is unknown so it falls back to a 4-byte write.
        bus, model = _bus_with_registers()
        _apply_register(
            {"peripheral": "TST", "register": "0x20", "value": "0x5"}, bus, None
        )
        self.assertEqual(model.writes, [(0x20, 4, 0x5)])


if __name__ == "__main__":
    unittest.main()
