"""DMAMUX / DMA request-routing tests.

A peripheral now emits a symbolic request line (SPI1_RX, USART3_TX, ADC1, ...)
with each DMA request. A stream that has been mapped to a request only responds
to that request; unmapped streams keep the permissive PAR+direction fallback.
"""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.dma import DmaPeripheral
from stmemu.peripherals.usart import Stm32UsartPeripheral


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


class _Src(PeripheralModel):
    """A data register that hands out a fixed byte on each read."""

    def __init__(self, value=0xA5):
        self.value = value

    def read(self, offset, size):
        return self.value & ((1 << (size * 8)) - 1)

    def write(self, offset, size, value):
        pass


_SRC_BASE = 0x40012000
_DMA_BASE = 0x40026000
_DR = 0x40


def _setup():
    src_svd = SvdPeripheral(
        name="SPI1", base_address=_SRC_BASE, size=0x400,
        registers=(SvdRegister(name="DR", offset=_DR),), interrupts=(),
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
        AddressRange(base=_SRC_BASE, end=_SRC_BASE + 0x400, peripheral=src_svd),
        AddressRange(base=_DMA_BASE, end=_DMA_BASE + 0x400, peripheral=dma_svd),
    )
    amap = AddressMap(device_name="T", peripherals=(src_svd, dma_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    bus._interrupts = _FakeNvic()
    emu = _FakeEmu()
    bus._emulator = emu
    src = _Src()
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("SPI1", src)
    bus.register_peripheral("DMA1", dma)
    return bus, src, dma, emu


def _arm(dma, stream, mar, ndtr=1, direction=None):
    direction = dma._DIR_P2M if direction is None else direction
    so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
    dma.write_register_value(so + dma._SxNDTR, ndtr)
    dma.write_register_value(so + dma._SxPAR, _SRC_BASE + _DR)
    dma.write_register_value(so + dma._SxM0AR, mar)
    cr = dma._SxCR_EN | dma._SxCR_MINC | (direction << dma._SxCR_DIR_SHIFT)
    dma.write(so + dma._SxCR, 4, cr)


def _ndtr(dma, stream):
    so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
    return dma.read_register_value(so + dma._SxNDTR)


class RequestRoutingTests(unittest.TestCase):
    def test_request_routes_to_mapped_stream_only(self):
        # Two streams both EN, same PAR+direction, distinguished only by their
        # mapped request. The matching request must drive the right one.
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)
        _arm(dma, 1, mar=0x300)
        dma.set_stream_request(0, "SPI1_RX")
        dma.set_stream_request(1, "SPI2_RX")

        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI2_RX")

        # Stream 1 (SPI2_RX) transferred; stream 0 (SPI1_RX) did not.
        self.assertEqual(_ndtr(dma, 0), 1, "SPI1_RX stream must stay idle")
        self.assertEqual(_ndtr(dma, 1), 0, "SPI2_RX stream must transfer")
        self.assertEqual(emu.mem_read(0x300, 1), bytes([0xA5]))
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0x00]))

    def test_tx_and_rx_requests_select_distinct_streams(self):
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)  # rx
        _arm(dma, 1, mar=0x300)  # also points at DR, p2m for test simplicity
        dma.set_stream_request(0, "SPI1_RX")
        dma.set_stream_request(1, "SPI1_TX")

        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(_ndtr(dma, 0), 0)
        self.assertEqual(_ndtr(dma, 1), 1, "TX-mapped stream ignores an RX request")

    def test_wrong_request_mapping_does_not_transfer(self):
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)
        dma.set_stream_request(0, "SPI1_RX")

        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="USART3_RX")

        self.assertEqual(_ndtr(dma, 0), 1, "mismatched request must not transfer")
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0x00]))

    def test_mapped_stream_ignores_unnamed_request(self):
        # A mapped stream is DMAMUX-routed: an unnamed request (no request
        # line) must not drive it, even though PAR+direction match.
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)
        dma.set_stream_request(0, "SPI1_RX")
        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request=None)
        self.assertEqual(_ndtr(dma, 0), 1)
        self.assertEqual(emu.mem_read(0x200, 1), b"\x00")

    def test_mapped_stream_accepts_its_request(self):
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)
        dma.set_stream_request(0, "SPI1_RX")
        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(_ndtr(dma, 0), 0)
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0xA5]))

    def test_fallback_par_direction_without_mapping(self):
        # No request mapping -> permissive PAR+direction routing still works,
        # even when the request carries a name.
        bus, src, dma, emu = _setup()
        _arm(dma, 0, mar=0x200)

        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(_ndtr(dma, 0), 0)
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0xA5]))

    def test_snapshot_restore_preserves_routing(self):
        bus, src, dma, emu = _setup()
        dma.set_stream_request(0, "SPI1_RX")
        dma.set_stream_request(1, "SPI2_RX")
        snap = dma.snapshot_state()

        bus2, src2, dma2, emu2 = _setup()
        dma2.restore_state(snap)
        _arm(dma2, 0, mar=0x200)
        _arm(dma2, 1, mar=0x300)

        # Restored mapping: a SPI2_RX request must drive stream 1, not 0.
        dma2.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI2_RX")
        self.assertEqual(_ndtr(dma2, 0), 1)
        self.assertEqual(_ndtr(dma2, 1), 0)


class BoardConfigRoutingTests(unittest.TestCase):
    def test_board_dma_config_maps_requests(self):
        from stmemu.board_config import apply_board_config
        bus, src, dma, emu = _setup()
        cfg = {
            "board": {
                "dma": {
                    "DMA1": {
                        "streams": {
                            0: {"request": "SPI1_RX"},
                            1: {"request": "SPI2_RX"},
                        }
                    }
                }
            }
        }
        msgs = apply_board_config(cfg, bus, source="test")
        self.assertTrue(any("2 stream request" in m for m in msgs), msgs)

        _arm(dma, 0, mar=0x200)
        _arm(dma, 1, mar=0x300)
        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI2_RX")
        self.assertEqual(_ndtr(dma, 1), 0)
        self.assertEqual(_ndtr(dma, 0), 1)

    def test_board_dmamux_config_maps_channels(self):
        from stmemu.board_config import apply_board_config
        bus, src, dma, emu = _setup()
        cfg = {
            "board": {
                "dmamux": {
                    "DMAMUX1": {
                        "channels": {
                            0: {"request": "SPI1_RX"},  # ch0 -> DMA1 stream0
                        }
                    }
                }
            }
        }
        msgs = apply_board_config(cfg, bus, source="test")
        self.assertTrue(any("dmamux" in m and "1 channel" in m for m in msgs), msgs)

        _arm(dma, 0, mar=0x200)
        dma.on_peripheral_request(_SRC_BASE + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(_ndtr(dma, 0), 0)
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0xA5]))


# ── Real USART RX DMA through the routing layer ──────────────────


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
_USART_BASE = 0x40004400


class UsartRxDmaRoutingTests(unittest.TestCase):
    def _setup(self):
        usart_svd = SvdPeripheral(
            name="USART3", base_address=_USART_BASE, size=0x400,
            registers=_USART_REGS,
            interrupts=(SvdInterrupt(name="USART3", value=39),),
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
            AddressRange(base=_USART_BASE, end=_USART_BASE + 0x400, peripheral=usart_svd),
            AddressRange(base=_DMA_BASE, end=_DMA_BASE + 0x400, peripheral=dma_svd),
        )
        amap = AddressMap(device_name="T", peripherals=(usart_svd, dma_svd), ranges=ranges)
        bus = PeripheralBus(amap)
        bus._interrupts = _FakeNvic()
        emu = _FakeEmu()
        bus._emulator = emu
        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=39)
        dma = DmaPeripheral(peripheral=dma_svd)
        bus.register_peripheral("USART3", uart)
        bus.register_peripheral("DMA1", dma)
        return bus, uart, dma, emu

    def test_usart_rx_dma_routes_via_request(self):
        bus, uart, dma, emu = self._setup()
        rdr = _USART_BASE + 0x24
        # Circular RX stream mapped to USART3_RX.
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 8)
        dma.write_register_value(so + dma._SxPAR, rdr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)
        dma.set_stream_request(0, "USART3_RX")

        uart.write(0x00, 4, (1 << 0) | (1 << 2))  # UE + RE
        uart.write(0x08, 4, uart._CR3_DMAR)        # CR3.DMAR
        uart.inject_rx_bytes(b"$GPGGA,")

        self.assertEqual(emu.mem_read(0x200, 7), b"$GPGGA,")

    def test_usart_rx_dma_blocked_by_wrong_mapping(self):
        bus, uart, dma, emu = self._setup()
        rdr = _USART_BASE + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 8)
        dma.write_register_value(so + dma._SxPAR, rdr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        dma.write(so + dma._SxCR, 4, dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC)
        dma.set_stream_request(0, "SPI1_RX")  # wrong mapping

        uart.write(0x00, 4, (1 << 0) | (1 << 2))
        uart.write(0x08, 4, uart._CR3_DMAR)
        uart.inject_rx_bytes(b"ABC")

        self.assertEqual(emu.mem_read(0x200, 3), b"\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
