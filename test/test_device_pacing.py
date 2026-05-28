"""Tests for autonomous external device pacing through bus tick loop."""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.peripherals.dma import DmaPeripheral
from stmemu.external.serial_line import SerialLine
from stmemu.external.ublox import UbloxGpsDevice


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

_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
)


def _make_svd(name, base, regs=(), interrupts=()):
    return SvdPeripheral(name=name, base_address=base, size=0x400,
                         registers=regs, interrupts=interrupts)


class _FakeNvic:
    def __init__(self):
        self.pending = {}
    def set_irq_pending(self, irq, pending=True):
        self.pending[irq] = pending
    def set_system_pending(self, name, pending=True):
        pass


class _FakeMemEmu:
    def __init__(self):
        self._mem = bytearray(0x1000)
    def mem_write(self, addr, data):
        off = addr & 0xFFF
        self._mem[off:off+len(data)] = data
    def mem_read(self, addr, size):
        off = addr & 0xFFF
        return bytes(self._mem[off:off+size])


# ── Autonomous GPS emission tests ────────────────────────────────


class AutonomousGpsTests(unittest.TestCase):
    def _make_setup(self, rate_cycles=100):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        ranges = (AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(usart_svd,), ranges=ranges)
        bus = PeripheralBus(amap)
        nvic = _FakeNvic()
        bus._interrupts = nvic

        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        bus.register_peripheral("USART1", uart)

        gps = UbloxGpsDevice(mode="nmea", rate_cycles=rate_cycles)
        line = SerialLine("gps0", uart=uart, device=gps, bus=bus)
        bus.attach_serial_line(line)

        return bus, uart, gps, line, nvic

    def test_no_emission_before_rate(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(50)
        data = uart.peek_tx_bytes()
        rx = list(uart._rx_fifo)
        self.assertEqual(len(rx), 0)

    def test_emission_at_rate(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(100)
        rx = list(uart._rx_fifo)
        self.assertGreater(len(rx), 0)
        rx_str = bytes(rx).decode("ascii", errors="replace")
        self.assertIn("$GPGGA,", rx_str)

    def test_repeated_ticks_produce_repeated_sentences(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(100)
        first_rx = len(uart._rx_fifo)
        uart._rx_fifo.clear()
        bus.tick(100)
        second_rx = len(uart._rx_fifo)
        self.assertGreater(second_rx, 0)

    def test_device_tx_event_emitted(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.event_log_enabled = True
        bus.tick(100)
        log = bus.drain_event_log()
        tx_events = [e for e in log if e.kind == "device_tx"]
        self.assertGreater(len(tx_events), 0)
        self.assertEqual(tx_events[0].source, "ublox")

    def test_byte_counters(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(100)
        self.assertGreater(line._total_rx_bytes, 0)

    def test_snapshot_preserves_timing(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(50)
        state = line.snapshot_state()
        gps._cycle_counter = 0
        line.restore_state(state)
        self.assertGreater(gps._cycle_counter, 0)

    def test_reset_clears_counters(self):
        bus, uart, gps, line, nvic = self._make_setup(rate_cycles=100)
        bus.tick(100)
        line.reset()
        self.assertEqual(line._total_rx_bytes, 0)
        self.assertEqual(line._total_tx_bytes, 0)


# ── GPS → USART → DMA circular path ─────────────────────────────


class GpsDmaCircularTests(unittest.TestCase):
    def test_autonomous_gps_fills_dma_buffer(self):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        dma_svd = _make_svd("DMA1", 0x40026000, _DMA_REGS,
            interrupts=(SvdInterrupt(name="DMA1_Stream0", value=11),))
        ranges = (
            AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),
            AddressRange(base=0x40026000, end=0x40026400, peripheral=dma_svd),
        )
        amap = AddressMap(device_name="TEST",
            peripherals=(usart_svd, dma_svd), ranges=ranges)
        bus = PeripheralBus(amap)
        nvic = _FakeNvic()
        bus._interrupts = nvic
        emu = _FakeMemEmu()
        bus._emulator = emu

        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        dma = DmaPeripheral(peripheral=dma_svd)
        bus.register_peripheral("USART1", uart)
        bus.register_peripheral("DMA1", dma)

        # Enable USART with DMA receive
        uart.write(0x00, 4, (1 << 0) | (1 << 2))  # UE + RE
        uart.write(0x08, 4, 1 << 6)  # CR3.DMAR

        # Configure DMA circular on stream 0
        rdr_addr = 0x40004400 + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 512)
        dma.write_register_value(so + dma._SxPAR, rdr_addr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        # Attach GPS
        gps = UbloxGpsDevice(mode="nmea", rate_cycles=100)
        line = SerialLine("gps0", uart=uart, device=gps, bus=bus)
        bus.attach_serial_line(line)

        # Tick enough for GPS to emit
        bus.tick(100)

        # Check memory buffer starts with NMEA
        data = emu.mem_read(0x200, 6)
        self.assertEqual(data, b"$GPGGA", "GPS NMEA should arrive via DMA")


# ── Event trace integration ──────────────────────────────────────


class DevicePacingEventTraceTests(unittest.TestCase):
    def test_event_trace_captures_device_tx(self):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        ranges = (AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(usart_svd,), ranges=ranges)
        bus = PeripheralBus(amap)
        bus.event_log_enabled = True

        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        bus.register_peripheral("USART1", uart)

        gps = UbloxGpsDevice(mode="nmea", rate_cycles=50)
        line = SerialLine("gps0", uart=uart, device=gps, bus=bus)
        bus.attach_serial_line(line)

        bus.tick(50)
        log = bus.drain_event_log()

        # Should have device_tx events
        tx_events = [e for e in log if e.kind == "device_tx"]
        self.assertGreater(len(tx_events), 0)
        self.assertEqual(tx_events[0].source, "ublox")
        self.assertGreater(tx_events[0].size, 0)

        # Should also have dma_request events from USART if DMAR were enabled
        # (not enabled here, so just device_tx)

    def test_event_breakpoint_on_device_tx(self):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        ranges = (AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(usart_svd,), ranges=ranges)
        bus = PeripheralBus(amap)

        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        bus.register_peripheral("USART1", uart)

        gps = UbloxGpsDevice(mode="nmea", rate_cycles=50)
        line = SerialLine("gps0", uart=uart, device=gps, bus=bus)
        bus.attach_serial_line(line)

        # Subscribe to device_tx events
        received = []
        bus.subscribe("device_tx", received.append)
        bus.tick(50)
        self.assertGreater(len(received), 0)
        self.assertEqual(received[0].kind, "device_tx")


if __name__ == "__main__":
    unittest.main()
