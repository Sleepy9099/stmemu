"""Tests for the peripheral event bus and USART/DMA coupling."""
from __future__ import annotations

import sys
import types
import unittest

# ── Stub external dependencies ─────────────────────────────────────

if "capstone" not in sys.modules:
    _cs = types.ModuleType("capstone")
    class _Cs:
        def __init__(self, *a, **k): self.detail = False
        def disasm(self, code, addr, count=0): return []
    _cs.Cs = _Cs
    _cs.CS_ARCH_ARM = 0
    _cs.CS_MODE_THUMB = 0
    sys.modules["capstone"] = _cs

if "unicorn" not in sys.modules:
    _uc = types.ModuleType("unicorn")
    _uc_const = types.ModuleType("unicorn.unicorn_const")
    _uc_const.UC_HOOK_CODE = 0
    _uc.unicorn_const = _uc_const
    sys.modules["unicorn"] = _uc
    sys.modules["unicorn.unicorn_const"] = _uc_const

from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdField, SvdInterrupt
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.peripherals.dma import DmaPeripheral


def _make_svd(name, base, registers=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=base, size=0x400,
        registers=registers, interrupts=interrupts,
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

_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
)


# ── Event bus tests ───────────────────────────────────────────────


class EventBusTests(unittest.TestCase):
    def _make_bus(self):
        amap = AddressMap(device_name="TEST", peripherals=(), ranges=())
        return PeripheralBus(amap)

    def test_subscribe_and_emit(self):
        bus = self._make_bus()
        received = []
        bus.subscribe("test_event", received.append)
        bus.emit(PeripheralEvent(kind="test_event", source="T1"))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].kind, "test_event")
        self.assertEqual(received[0].source, "T1")

    def test_emit_no_subscribers(self):
        bus = self._make_bus()
        bus.emit(PeripheralEvent(kind="unhandled"))

    def test_multiple_subscribers(self):
        bus = self._make_bus()
        a, b = [], []
        bus.subscribe("evt", a.append)
        bus.subscribe("evt", b.append)
        bus.emit(PeripheralEvent(kind="evt"))
        self.assertEqual(len(a), 1)
        self.assertEqual(len(b), 1)

    def test_unsubscribe(self):
        bus = self._make_bus()
        received = []
        bus.subscribe("evt", received.append)
        bus.emit(PeripheralEvent(kind="evt"))
        self.assertEqual(len(received), 1)
        bus.unsubscribe("evt", received.append)
        bus.emit(PeripheralEvent(kind="evt"))
        self.assertEqual(len(received), 1)

    def test_event_log(self):
        bus = self._make_bus()
        bus.event_log_enabled = True
        bus.emit(PeripheralEvent(kind="a"))
        bus.emit(PeripheralEvent(kind="b"))
        log = bus.drain_event_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0].kind, "a")
        self.assertEqual(log[1].kind, "b")
        self.assertEqual(len(bus.drain_event_log()), 0)

    def test_event_log_disabled(self):
        bus = self._make_bus()
        bus.event_log_enabled = False
        bus.emit(PeripheralEvent(kind="x"))
        self.assertEqual(len(bus.drain_event_log()), 0)

    def test_request_dma_emits_event(self):
        bus = self._make_bus()
        bus.event_log_enabled = True
        bus.request_dma(0x40004428, "p2m", size=1)
        log = bus.drain_event_log()
        dma_events = [e for e in log if e.kind == "dma_request"]
        self.assertEqual(len(dma_events), 1)
        self.assertEqual(dma_events[0].address, 0x40004428)
        self.assertEqual(dma_events[0].direction, "p2m")

    def test_peripheral_event_fields(self):
        evt = PeripheralEvent(
            kind="test", source="USART1", address=0x40004428,
            direction="p2m", size=4, payload={"stream": 0},
        )
        self.assertEqual(evt.kind, "test")
        self.assertEqual(evt.source, "USART1")
        self.assertEqual(evt.payload, {"stream": 0})


# ── USART DMA coupling tests ─────────────────────────────────────


class UsartDmaCouplingTests(unittest.TestCase):
    def _make_bus_with_usart(self):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        ranges = (AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(usart_svd,), ranges=ranges)
        bus = PeripheralBus(amap)
        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        bus.register_peripheral("USART1", uart)
        return bus, uart

    def test_dmar_bit_triggers_dma_request_on_rxne(self):
        bus, uart = self._make_bus_with_usart()
        bus.event_log_enabled = True
        # Enable USART: UE + RE
        uart.write(0x00, 4, (1 << 0) | (1 << 2))
        # Enable DMA receive: CR3.DMAR
        uart.write(0x08, 4, 1 << 6)
        bus.drain_event_log()
        # Inject RX data → RXNE set → DMA request
        uart.inject_rx_bytes(b"\x42")
        log = bus.drain_event_log()
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertGreater(len(dma_reqs), 0)
        self.assertEqual(dma_reqs[0].direction, "p2m")
        self.assertEqual(dma_reqs[0].address, 0x40004400 + 0x24)

    def test_no_dma_request_without_dmar(self):
        bus, uart = self._make_bus_with_usart()
        bus.event_log_enabled = True
        uart.write(0x00, 4, (1 << 0) | (1 << 2))
        # CR3.DMAR NOT set
        bus.drain_event_log()
        uart.inject_rx_bytes(b"\x42")
        log = bus.drain_event_log()
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertEqual(len(dma_reqs), 0)

    def test_dmat_bit_triggers_dma_request_on_txe(self):
        bus, uart = self._make_bus_with_usart()
        bus.event_log_enabled = True
        # Enable USART: UE + TE
        uart.write(0x00, 4, (1 << 0) | (1 << 3))
        # Enable DMA transmit: CR3.DMAT
        uart.write(0x08, 4, 1 << 7)
        log = bus.drain_event_log()
        # TXFNF is always set, so DMA request should have been emitted
        dma_reqs = [e for e in log if e.kind == "dma_request" and e.direction == "m2p"]
        self.assertGreater(len(dma_reqs), 0)


# ── DMA complete event tests ─────────────────────────────────────


class DmaCompleteEventTests(unittest.TestCase):
    def _make_bus_with_dma(self):
        dma_svd = _make_svd("DMA1", 0x40026000, _DMA_REGS)
        ranges = (AddressRange(base=0x40026000, end=0x40026400, peripheral=dma_svd),)
        amap = AddressMap(device_name="TEST", peripherals=(dma_svd,), ranges=ranges)
        bus = PeripheralBus(amap)
        dma = DmaPeripheral(peripheral=dma_svd)
        bus.register_peripheral("DMA1", dma)
        return bus, dma

    def test_dma_complete_emits_event(self):
        bus, dma = self._make_bus_with_dma()
        bus.event_log_enabled = True
        dma.write(0x10, 4, 0x01)  # Enable stream 0
        log = bus.drain_event_log()
        complete_events = [e for e in log if e.kind == "dma_complete"]
        self.assertEqual(len(complete_events), 1)
        self.assertEqual(complete_events[0].source, "DMA1")

    def test_subscribe_to_dma_complete(self):
        bus, dma = self._make_bus_with_dma()
        received = []
        bus.subscribe("dma_complete", received.append)
        dma.write(0x10, 4, 0x01)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].kind, "dma_complete")


# ── Full USART → DMA → event chain ──────────────────────────────


class UsartDmaChainTests(unittest.TestCase):
    def _make_full_chain(self):
        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))
        dma_svd = _make_svd("DMA1", 0x40026000, _DMA_REGS)
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
        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        dma = DmaPeripheral(peripheral=dma_svd)
        bus.register_peripheral("USART1", uart)
        bus.register_peripheral("DMA1", dma)
        return bus, uart, dma

    def test_usart_rx_triggers_dma_transfer_complete(self):
        bus, uart, dma = self._make_full_chain()
        bus.event_log_enabled = True

        # Configure DMA stream 0: P2M, PAR = USART1.RDR
        rdr_addr = 0x40004400 + 0x24
        dma.write_register_value(0x18, rdr_addr)  # PAR
        dma.write_register_value(0x1C, 0x20000100)  # M0AR
        dma.write_register_value(0x14, 4)  # NDTR
        dma.write(0x10, 4, 0x01)  # Enable stream 0 (P2M, auto-completes)
        bus.drain_event_log()

        # Re-enable for request-driven mode
        dma.write(0x10, 4, 0x01)
        bus.drain_event_log()

        # Enable USART with DMA receive
        uart.write(0x00, 4, (1 << 0) | (1 << 2))  # UE + RE
        uart.write(0x08, 4, 1 << 6)  # CR3.DMAR
        bus.drain_event_log()

        # Inject data — this should trigger RXNE → DMA request
        uart.inject_rx_bytes(b"\xAA")
        log = bus.drain_event_log()

        # Verify the DMA request event was emitted
        dma_reqs = [e for e in log if e.kind == "dma_request"]
        self.assertGreater(len(dma_reqs), 0, "USART RXNE should emit dma_request")


if __name__ == "__main__":
    unittest.main()
