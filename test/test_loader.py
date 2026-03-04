from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from stmemu.core.loader import load_firmware


def _build_test_elf() -> bytes:
    flash_data = (
        (0x20002000).to_bytes(4, "little")
        + (0x08000041).to_bytes(4, "little")
        + b"\x00\xBF\x70\x47"
    )
    sram_data = b"\x11\x22"

    ehsize = 52
    phentsize = 32
    phnum = 2
    phoff = ehsize
    flash_offset = ehsize + (phentsize * phnum)
    sram_offset = flash_offset + len(flash_data)

    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        40,
        1,
        0x08000041,
        phoff,
        0,
        0,
        ehsize,
        phentsize,
        phnum,
        0,
        0,
        0,
    )
    ph_flash = struct.pack(
        "<IIIIIIII",
        1,
        flash_offset,
        0x08000000,
        0x08000000,
        len(flash_data),
        len(flash_data),
        5,
        0x1000,
    )
    ph_sram = struct.pack(
        "<IIIIIIII",
        1,
        sram_offset,
        0x20000000,
        0x20000000,
        len(sram_data),
        8,
        6,
        0x1000,
    )
    return header + ph_flash + ph_sram + flash_data + sram_data


def _build_vma_lma_elf() -> bytes:
    flash_data = (
        (0x20002000).to_bytes(4, "little")
        + (0x08000041).to_bytes(4, "little")
    )
    ram_init = b"\xAA\xBB\xCC\xDD"

    ehsize = 52
    phentsize = 32
    phnum = 2
    phoff = ehsize
    flash_offset = ehsize + (phentsize * phnum)
    ram_offset = flash_offset + len(flash_data)

    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        40,
        1,
        0x08000041,
        phoff,
        0,
        0,
        ehsize,
        phentsize,
        phnum,
        0,
        0,
        0,
    )
    ph_flash = struct.pack(
        "<IIIIIIII",
        1,
        flash_offset,
        0x08000000,
        0x08000000,
        len(flash_data),
        len(flash_data),
        5,
        0x1000,
    )
    ph_ram = struct.pack(
        "<IIIIIIII",
        1,
        ram_offset,
        0x20000000,
        0x08000100,
        len(ram_init),
        8,
        6,
        0x1000,
    )
    return header + ph_flash + ph_ram + flash_data + ram_init


class LoadFirmwareTests(unittest.TestCase):
    def _write_temp_file(self, payload: bytes) -> Path:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        with tmp:
            tmp.write(payload)
        return Path(tmp.name)

    def test_load_raw_binary_uses_supplied_base(self) -> None:
        path = self._write_temp_file(b"\x01\x02\x03\x04")

        firmware = load_firmware(path, base_addr=0x08000000)

        self.assertEqual(firmware.format, "bin")
        self.assertEqual(firmware.vector_base, 0x08000000)
        self.assertEqual(len(firmware.segments), 1)
        self.assertEqual(firmware.segments[0].address, 0x08000000)
        self.assertEqual(firmware.segments[0].data, b"\x01\x02\x03\x04")

    def test_load_elf_uses_embedded_segments(self) -> None:
        path = self._write_temp_file(_build_test_elf())

        firmware = load_firmware(path)

        self.assertEqual(firmware.format, "elf")
        self.assertEqual(firmware.entry_point, 0x08000041)
        self.assertEqual(firmware.vector_base, 0x08000000)
        self.assertEqual(len(firmware.segments), 2)
        self.assertEqual(firmware.segments[0].address, 0x08000000)
        self.assertEqual(firmware.segments[1].address, 0x20000000)
        self.assertEqual(firmware.segments[1].data, b"\x11\x22" + (b"\x00" * 6))

    def test_load_elf_uses_runtime_vaddr_for_ram_init(self) -> None:
        path = self._write_temp_file(_build_vma_lma_elf())

        firmware = load_firmware(path)

        self.assertEqual(len(firmware.segments), 3)
        segments = {segment.address: segment.data for segment in firmware.segments}
        self.assertEqual(segments[0x20000000], b"\xAA\xBB\xCC\xDD" + (b"\x00" * 4))
        self.assertEqual(segments[0x08000100], b"\xAA\xBB\xCC\xDD")


if __name__ == "__main__":
    unittest.main()
