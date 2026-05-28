"""DMA element-size (PSIZE/MSIZE) regression tests.

The DMA engine used to access peripheral data registers one byte at a time,
ignoring the configured PSIZE. For a 16-bit data register (ADC DR, a 16-bit
SPI frame, ...) that read the register twice and assembled the wrong value.
These tests pin the peripheral side to PSIZE-wide transactions.
"""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.dma import DmaPeripheral


class _FakeEmu:
    def __init__(self, size: int = 0x1000):
        self._mem = bytearray(size)

    def mem_write(self, addr, data):
        off = addr & 0xFFF
        self._mem[off:off + len(data)] = data

    def mem_read(self, addr, size):
        off = addr & 0xFFF
        return bytes(self._mem[off:off + size])


class _FakeNvic:
    def set_irq_pending(self, *a, **k):
        pass

    def set_system_pending(self, *a, **k):
        pass


class _Reg16(PeripheralModel):
    """A 16-bit data-register peripheral that records access widths."""

    def __init__(self, rx=(0xBEEF, 0xCAFE)):
        self._rx = list(rx)
        self._i = 0
        self.read_sizes: list[int] = []
        self.writes: list[tuple[int, int]] = []  # (size, value)

    def read(self, offset, size):
        self.read_sizes.append(size)
        val = self._rx[self._i % len(self._rx)]
        self._i += 1
        return val & ((1 << (size * 8)) - 1)

    def write(self, offset, size, value):
        self.writes.append((size, value & ((1 << (size * 8)) - 1)))


_ADC_BASE = 0x40012000
_DMA_BASE = 0x40026000
_DR_OFF = 0x40


def _make_setup(rx=(0xBEEF, 0xCAFE)):
    adc_svd = SvdPeripheral(
        name="ADC1", base_address=_ADC_BASE, size=0x400,
        registers=(SvdRegister(name="DR", offset=_DR_OFF),), interrupts=(),
    )
    dma_svd = SvdPeripheral(
        name="DMA1", base_address=_DMA_BASE, size=0x400,
        registers=(
            SvdRegister(name="LISR", offset=0x00),
            SvdRegister(name="HISR", offset=0x04),
            SvdRegister(name="LIFCR", offset=0x08),
            SvdRegister(name="HIFCR", offset=0x0C),
        ),
        interrupts=(SvdInterrupt(name="DMA1_Stream0", value=11),),
    )
    ranges = (
        AddressRange(base=_ADC_BASE, end=_ADC_BASE + 0x400, peripheral=adc_svd),
        AddressRange(base=_DMA_BASE, end=_DMA_BASE + 0x400, peripheral=dma_svd),
    )
    amap = AddressMap(device_name="T", peripherals=(adc_svd, dma_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    bus._interrupts = _FakeNvic()
    emu = _FakeEmu()
    bus._emulator = emu
    adc = _Reg16(rx=rx)
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("ADC1", adc)
    bus.register_peripheral("DMA1", dma)
    return bus, adc, dma, emu


def _program(dma, stream, par, mar, ndtr, direction, psize, msize):
    so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
    dma.write_register_value(so + dma._SxNDTR, ndtr)
    dma.write_register_value(so + dma._SxPAR, par)
    dma.write_register_value(so + dma._SxM0AR, mar)
    cr = (
        dma._SxCR_EN | dma._SxCR_MINC
        | (direction << dma._SxCR_DIR_SHIFT)
        | (psize << dma._SxCR_PSIZE_SHIFT)
        | (msize << dma._SxCR_MSIZE_SHIFT)
    )
    dma.write(so + dma._SxCR, 4, cr)


class DmaItemSizeTests(unittest.TestCase):
    def test_p2m_16bit_reads_peripheral_as_halfword(self):
        bus, adc, dma, emu = _make_setup()
        par, mar = _ADC_BASE + _DR_OFF, 0x200
        _program(dma, 0, par, mar, ndtr=2, direction=dma._DIR_P2M, psize=1, msize=1)
        dma.on_peripheral_request(par, "p2m", 2)
        dma.on_peripheral_request(par, "p2m", 2)

        self.assertEqual(adc.read_sizes, [2, 2], "16-bit DR read as halfwords")
        # 0xBEEF, 0xCAFE little-endian, contiguous.
        self.assertEqual(emu.mem_read(mar, 4), bytes([0xEF, 0xBE, 0xFE, 0xCA]))

    def test_m2p_16bit_writes_peripheral_as_halfword(self):
        bus, adc, dma, emu = _make_setup()
        par, mar = _ADC_BASE + _DR_OFF, 0x300
        emu.mem_write(mar, bytes([0x34, 0x12, 0x78, 0x56]))  # 0x1234, 0x5678 LE
        _program(dma, 1, par, mar, ndtr=2, direction=dma._DIR_M2P, psize=1, msize=1)
        dma.on_peripheral_request(par, "m2p", 2)
        dma.on_peripheral_request(par, "m2p", 2)

        self.assertEqual(adc.writes, [(2, 0x1234), (2, 0x5678)])

    def test_mismatched_msize_keeps_memory_contiguous(self):
        # PSIZE 8-bit, MSIZE 16-bit: NDTR counts peripheral items (bytes); the
        # memory side packs them contiguously (matching hardware packing), so a
        # larger MSIZE must not spread the bytes out with gaps.
        bus, adc, dma, emu = _make_setup(rx=(0x11, 0x22, 0x33, 0x44))
        par, mar = _ADC_BASE + _DR_OFF, 0x400
        _program(dma, 0, par, mar, ndtr=4, direction=dma._DIR_P2M, psize=0, msize=1)
        for _ in range(4):
            dma.on_peripheral_request(par, "p2m", 1)
        self.assertEqual(adc.read_sizes, [1, 1, 1, 1], "8-bit DR read as bytes")
        self.assertEqual(emu.mem_read(mar, 4), bytes([0x11, 0x22, 0x33, 0x44]))


if __name__ == "__main__":
    unittest.main()
