"""Tests for DMA circular mode and USART RX DMA path."""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.dma import DmaPeripheral
from stmemu.peripherals.usart import Stm32UsartPeripheral


_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
)

_USART_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="CR3", offset=0x08),
    SvdRegister(name="BRR", offset=0x0C),
    SvdRegister(name="RQR", offset=0x18),
    SvdRegister(name="ISR", offset=0x1C),
    SvdRegister(name="ICR", offset=0x20),
    SvdRegister(name="RDR", offset=0x24),
    SvdRegister(name="TDR", offset=0x28),
)


def _make_svd(name, base, registers=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=base, size=0x400,
        registers=registers, interrupts=interrupts,
    )


class _FakeNvic:
    def __init__(self):
        self.pending: dict[int, bool] = {}
    def set_irq_pending(self, irq, pending=True):
        self.pending[irq] = pending
    def set_system_pending(self, name, pending=True):
        pass


class _FakeEmu:
    """Minimal emulator for DMA memory operations."""
    def __init__(self):
        self._mem: bytearray = bytearray(0x1000)

    def mem_write(self, addr, data):
        offset = addr & 0xFFF
        self._mem[offset : offset + len(data)] = data

    def mem_read(self, addr, size):
        offset = addr & 0xFFF
        return bytes(self._mem[offset : offset + size])


def _make_dma_bus():
    dma_svd = _make_svd("DMA1", 0x40026000, _DMA_REGS,
        interrupts=(SvdInterrupt(name="DMA1_Stream0", value=11),))
    ranges = (AddressRange(base=0x40026000, end=0x40026400, peripheral=dma_svd),)
    amap = AddressMap(device_name="TEST", peripherals=(dma_svd,), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    emu = _FakeEmu()
    bus._emulator = emu
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("DMA1", dma)
    return bus, dma, nvic, emu


def _make_usart_dma_bus():
    dma_svd = _make_svd("DMA1", 0x40026000, _DMA_REGS,
        interrupts=(SvdInterrupt(name="DMA1_Stream0", value=11),))
    usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
        interrupts=(SvdInterrupt(name="USART1", value=37),))
    ranges = (
        AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),
        AddressRange(base=0x40026000, end=0x40026400, peripheral=dma_svd),
    )
    amap = AddressMap(
        device_name="TEST",
        peripherals=(usart_svd, dma_svd),
        ranges=ranges,
    )
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    emu = _FakeEmu()
    bus._emulator = emu
    uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("USART1", uart)
    bus.register_peripheral("DMA1", dma)
    return bus, uart, dma, nvic, emu


# ── Circular mode tests ──────────────────────────────────────────


class DmaCircularTests(unittest.TestCase):
    def test_circular_enable_does_not_auto_complete(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x20000100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC
        dma.write(so + dma._SxCR, 4, cr)
        self.assertTrue(
            dma.read_register_value(so + dma._SxCR) & dma._SxCR_EN,
            "EN should stay set in circular mode",
        )
        ndtr = dma.read_register_value(so + dma._SxNDTR)
        self.assertEqual(ndtr, 4, "NDTR should not change until request")

    def test_circular_item_transfer(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        dma.on_peripheral_request(0x40004424, "p2m")
        ndtr = dma.read_register_value(so + dma._SxNDTR)
        self.assertEqual(ndtr, 3)

    def test_circular_wraps_ndtr(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        for _ in range(4):
            dma.on_peripheral_request(0x40004424, "p2m")

        ndtr = dma.read_register_value(so + dma._SxNDTR)
        self.assertEqual(ndtr, 4, "NDTR should reload after wrap")
        self.assertTrue(
            dma.read_register_value(so + dma._SxCR) & dma._SxCR_EN,
            "EN should remain set after circular wrap",
        )

    def test_circular_tcif_on_wrap(self):
        bus, dma, nvic, emu = _make_dma_bus()
        bus.event_log_enabled = True
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 2)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)
        bus.drain_event_log()

        dma.on_peripheral_request(0x40004424, "p2m")
        dma.on_peripheral_request(0x40004424, "p2m")

        lisr = dma.read_register_value(dma._LISR)
        self.assertTrue(lisr & (1 << 5), "TCIF should be set on wrap")
        log = bus.drain_event_log()
        complete = [e for e in log if e.kind == "dma_complete"]
        self.assertEqual(len(complete), 1)

    def test_circular_htif_at_midpoint(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        dma.on_peripheral_request(0x40004424, "p2m")
        lisr = dma.read_register_value(dma._LISR)
        self.assertFalse(lisr & (1 << 4), "HTIF should not be set after 1/4")

        dma.on_peripheral_request(0x40004424, "p2m")
        lisr = dma.read_register_value(dma._LISR)
        self.assertTrue(lisr & (1 << 4), "HTIF should be set at midpoint")

    def test_circular_dma_half_event(self):
        bus, dma, nvic, emu = _make_dma_bus()
        bus.event_log_enabled = True
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)
        bus.drain_event_log()

        dma.on_peripheral_request(0x40004424, "p2m")
        self.assertEqual(len([e for e in bus.drain_event_log() if e.kind == "dma_half"]), 0)

        dma.on_peripheral_request(0x40004424, "p2m")
        log = bus.drain_event_log()
        half_events = [e for e in log if e.kind == "dma_half"]
        self.assertEqual(len(half_events), 1)
        self.assertEqual(half_events[0].source, "DMA1")

    def test_circular_tcie_irq(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 2)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_TCIE | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        dma.on_peripheral_request(0x40004424, "p2m")
        dma.on_peripheral_request(0x40004424, "p2m")
        self.assertTrue(nvic.pending.get(11, False))

    def test_circular_htie_irq(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_HTIE | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        dma.on_peripheral_request(0x40004424, "p2m")
        self.assertFalse(nvic.pending.get(11, False))
        dma.on_peripheral_request(0x40004424, "p2m")
        self.assertTrue(nvic.pending.get(11, False))

    def test_circular_memory_increment(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        for _ in range(4):
            dma.on_peripheral_request(0x40004424, "p2m")

        for _ in range(2):
            dma.on_peripheral_request(0x40004424, "p2m")

        self.assertEqual(dma._stream_pos[0], 2)

    def test_normal_mode_still_bulk_completes(self):
        bus, dma, nvic, emu = _make_dma_bus()
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, 0x40004424)
        dma.write_register_value(so + dma._SxM0AR, 0x100)
        dma.write(so + dma._SxCR, 4, dma._SxCR_EN)
        lisr = dma.read_register_value(dma._LISR)
        self.assertTrue(lisr & (1 << 5))
        cr = dma.read_register_value(so + dma._SxCR)
        self.assertFalse(cr & dma._SxCR_EN)


# ── USART RX → DMA circular path ─────────────────────────────────


class UsartDmaCircularTests(unittest.TestCase):
    def test_usart_rx_fills_circular_buffer(self):
        bus, uart, dma, nvic, emu = _make_usart_dma_bus()

        rdr_addr = 0x40004400 + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 8)
        dma.write_register_value(so + dma._SxPAR, rdr_addr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        uart.write(0x00, 4, (1 << 0) | (1 << 2))  # UE + RE
        uart.write(0x08, 4, 1 << 6)  # CR3.DMAR

        uart.inject_rx_bytes(b"$GPGGA,")
        data = emu.mem_read(0x200, 7)
        self.assertEqual(data, b"$GPGGA,")

    def test_usart_rx_circular_wraps(self):
        bus, uart, dma, nvic, emu = _make_usart_dma_bus()

        rdr_addr = 0x40004400 + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, rdr_addr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        uart.write(0x00, 4, (1 << 0) | (1 << 2))
        uart.write(0x08, 4, 1 << 6)

        uart.inject_rx_bytes(b"ABCDEF")
        first4 = emu.mem_read(0x200, 4)
        self.assertEqual(first4, b"EFCD", "buffer should wrap: EF overwrites AB")

    def test_usart_rx_dma_tcif_on_wrap(self):
        bus, uart, dma, nvic, emu = _make_usart_dma_bus()
        bus.event_log_enabled = True

        rdr_addr = 0x40004400 + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 4)
        dma.write_register_value(so + dma._SxPAR, rdr_addr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC | dma._SxCR_TCIE
        dma.write(so + dma._SxCR, 4, cr)
        bus.drain_event_log()

        uart.write(0x00, 4, (1 << 0) | (1 << 2))
        uart.write(0x08, 4, 1 << 6)
        bus.drain_event_log()

        uart.inject_rx_bytes(b"ABCD")

        lisr = dma.read_register_value(dma._LISR)
        self.assertTrue(lisr & (1 << 5), "TCIF0 should be set after 4 bytes")
        self.assertTrue(nvic.pending.get(11, False), "DMA IRQ should pend")

        log = bus.drain_event_log()
        complete = [e for e in log if e.kind == "dma_complete"]
        self.assertGreater(len(complete), 0)


if __name__ == "__main__":
    unittest.main()
