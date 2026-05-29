"""Tests for SPI DMA transfers driving on-board SPI sensors.

These exercise the firmware probe path used by ArduPilot/PX4 on real
hardware: SPI configured with TX/RX DMA streams, CS asserted on the
sensor's GPIO, a few bytes clocked out, and the response read back from
memory after DMA TC. Covers both legacy DR (F4/F7) and H7-style TXDR/RXDR
register layouts.
"""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.spi import SpiPeripheral
from stmemu.peripherals.dma import DmaPeripheral
from stmemu.external.spi_imu import (
    Icm42688Device,
    Bmi088AccelDevice,
    Bmi088GyroDevice,
)
from stmemu.external.fram import FramFm25v02a


_SPI_LEGACY_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="SR", offset=0x08, reset_value=0x02),
    SvdRegister(name="DR", offset=0x0C),
)

_SPI_H7_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="CFG1", offset=0x08),
    SvdRegister(name="CFG2", offset=0x0C),
    SvdRegister(name="SR", offset=0x14),
    SvdRegister(name="IFCR", offset=0x18),
    SvdRegister(name="TXDR", offset=0x20),
    SvdRegister(name="RXDR", offset=0x30),
)

_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
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
    def __init__(self, size: int = 0x4000):
        self._mem = bytearray(size)

    def mem_write(self, addr, data):
        off = addr & 0x3FFF
        self._mem[off:off + len(data)] = data

    def mem_read(self, addr, size):
        off = addr & 0x3FFF
        return bytes(self._mem[off:off + size])


def _make_legacy_setup():
    spi_svd = _make_svd("SPI1", 0x40013000, _SPI_LEGACY_REGS,
                        interrupts=(SvdInterrupt(name="SPI1", value=35),))
    dma_svd = _make_svd("DMA2", 0x40026400, _DMA_REGS,
                        interrupts=(
                            SvdInterrupt(name="DMA2_Stream0", value=56),
                            SvdInterrupt(name="DMA2_Stream3", value=59),
                        ))
    ranges = (
        AddressRange(base=0x40013000, end=0x40013400, peripheral=spi_svd),
        AddressRange(base=0x40026400, end=0x40026800, peripheral=dma_svd),
    )
    amap = AddressMap(device_name="TEST",
                      peripherals=(spi_svd, dma_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    emu = _FakeEmu()
    bus._emulator = emu

    spi = SpiPeripheral(peripheral=spi_svd, irq=35)
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("SPI1", spi)
    bus.register_peripheral("DMA2", dma)
    return bus, spi, dma, nvic, emu


def _make_h7_setup():
    spi_svd = _make_svd("SPI1", 0x40013000, _SPI_H7_REGS,
                        interrupts=(SvdInterrupt(name="SPI1", value=35),))
    dma_svd = _make_svd("DMA1", 0x40020000, _DMA_REGS,
                        interrupts=(
                            SvdInterrupt(name="DMA1_Stream0", value=11),
                            SvdInterrupt(name="DMA1_Stream1", value=12),
                        ))
    ranges = (
        AddressRange(base=0x40013000, end=0x40013400, peripheral=spi_svd),
        AddressRange(base=0x40020000, end=0x40020400, peripheral=dma_svd),
    )
    amap = AddressMap(device_name="TEST",
                      peripherals=(spi_svd, dma_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic
    emu = _FakeEmu()
    bus._emulator = emu

    spi = SpiPeripheral(peripheral=spi_svd, irq=35)
    dma = DmaPeripheral(peripheral=dma_svd)
    bus.register_peripheral("SPI1", spi)
    bus.register_peripheral("DMA1", dma)
    return bus, spi, dma, nvic, emu


def _setup_dma_stream(
    dma: DmaPeripheral, stream: int, par: int, mar: int, ndtr: int,
    direction: str, *, tcie: bool = False,
) -> int:
    """Program DMA stream registers and return the CR value to enable with."""
    so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
    dma.write_register_value(so + dma._SxNDTR, ndtr)
    dma.write_register_value(so + dma._SxPAR, par)
    dma.write_register_value(so + dma._SxM0AR, mar)
    cr = dma._SxCR_EN | dma._SxCR_MINC
    if direction == "m2p":
        cr |= (dma._DIR_M2P << dma._SxCR_DIR_SHIFT)
    if tcie:
        cr |= dma._SxCR_TCIE
    return cr


# ── Legacy SPI (DR + CR2 layout) DMA tests ───────────────────────


class LegacySpiDmaProbeTests(unittest.TestCase):
    def test_icm42688_whoami_via_full_duplex_dma(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        # AP_InertialSensor probe: send 0x80|0x75 (read WHOAMI), then a
        # dummy byte to clock the response out.
        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))

        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m", tcie=True)
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        # Enable SPI with DMA: CR2 first (TXDMAEN | RXDMAEN), then CR1.SPE.
        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        rx = emu.mem_read(rx_addr, 2)
        # Byte 0 echoes the address byte (0xFF dispatch), byte 1 is WHOAMI.
        self.assertEqual(rx[1], 0x47, "ICM-42688 WHOAMI should arrive via DMA")

    def test_bmi088_accel_dummy_byte_handled(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        accel = Bmi088AccelDevice(name="bmi_a")
        accel.cs_select()
        spi.attach_device(accel)

        tx_addr = 0x100
        rx_addr = 0x200
        # BMI088 accel read: address byte (read bit set), dummy, then data.
        emu.mem_write(tx_addr, bytes([0x80 | 0x00, 0x00, 0x00]))

        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 3, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 3, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        rx = emu.mem_read(rx_addr, 3)
        # Byte 0: echo of address, byte 1: dummy (0xFF), byte 2: WHOAMI 0x1E.
        self.assertEqual(rx[2], 0x1E, "BMI088 accel WHOAMI lands after dummy")

    def test_bmi088_gyro_whoami_no_dummy(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        gyro = Bmi088GyroDevice(name="bmi_g")
        gyro.cs_select()
        spi.attach_device(gyro)

        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x00, 0x00]))

        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        rx = emu.mem_read(rx_addr, 2)
        self.assertEqual(rx[1], 0x0F, "BMI088 gyro WHOAMI no dummy")

    def test_fram_rdid_via_dma(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        fram = FramFm25v02a(name="fram0")
        fram.cs_select()
        spi.attach_device(fram)

        tx_addr = 0x100
        rx_addr = 0x200
        # RDID opcode + 9 dummy bytes to clock out the full JEDEC response.
        emu.mem_write(tx_addr, bytes([0x9F] + [0x00] * 9))

        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 10, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 10, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        rx = emu.mem_read(rx_addr, 10)
        # rx[0] echoes the opcode (0xFF); rx[1..9] are the 9 JEDEC bytes.
        # Cypress-style RDID: six 0x7F continuation codes, 0xC2 manufacturer,
        # then the bytes AP_RAMTRON actually matches for the FM25V02A:
        # id1=0x22 and id2=0x08.
        self.assertEqual(list(rx[1:7]), [0x7F] * 6)
        self.assertEqual(rx[7], 0xC2)
        self.assertEqual(rx[8], 0x22, "AP_RAMTRON id1 for FM25V02A")
        self.assertEqual(rx[9], 0x08, "AP_RAMTRON id2 for FM25V02A")


# ── DMA completion semantics ────────────────────────────────────


class SpiDmaCompletionTests(unittest.TestCase):
    def test_dma_tc_fires_after_burst(self):
        bus, spi, dma, nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))

        dr_addr = 0x40013000 + 0x0C
        # Stream 0 (RX): TCIE on, IRQ 56.
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m", tcie=True)
        # Stream 3 (TX): TCIE on, IRQ 59.
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p", tcie=True)
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        lisr = dma.read_register_value(dma._LISR)
        # TCIF0 (stream 0) and TCIF3 (stream 3) per _STREAM_FLAG_BITS.
        self.assertTrue(lisr & (1 << 5), "RX stream TCIF0")
        self.assertTrue(lisr & (1 << 27), "TX stream TCIF3")
        # Streams should self-disable.
        rx_cr_after = dma.read_register_value(dma._STREAM_BASE + dma._SxCR)
        tx_cr_after = dma.read_register_value(
            dma._STREAM_BASE + 3 * dma._STREAM_STRIDE + dma._SxCR,
        )
        self.assertFalse(rx_cr_after & dma._SxCR_EN, "RX stream EN cleared")
        self.assertFalse(tx_cr_after & dma._SxCR_EN, "TX stream EN cleared")
        # TC IRQs pending.
        self.assertTrue(nvic.pending.get(56, False))
        self.assertTrue(nvic.pending.get(59, False))

    def test_dma_complete_events_emitted(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        bus.event_log_enabled = True
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))

        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)
        bus.drain_event_log()

        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        log = bus.drain_event_log()
        complete = [e for e in log if e.kind == "dma_complete"]
        # Both streams should fire dma_complete.
        streams_completed = {e.payload["stream"] for e in complete}
        self.assertIn(0, streams_completed)
        self.assertIn(3, streams_completed)


# ── CS transaction correctness ──────────────────────────────────


class SpiDmaCsTransactionTests(unittest.TestCase):
    def test_cs_release_resets_transaction(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        spi.attach_device(imu)

        # First transaction with CS asserted: read WHOAMI.
        imu.cs_select()
        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))
        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)
        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)
        self.assertEqual(emu.mem_read(rx_addr, 2)[1], 0x47)

        # CS release between transactions resets device state.
        imu.cs_release()
        self.assertEqual(imu._state, "IDLE")

        # Second transaction, fresh frame: read WHOAMI again.
        imu.cs_select()
        emu.mem_write(tx_addr + 0x10, bytes([0x80 | 0x75, 0x00]))
        rx2 = rx_addr + 0x10
        rx_cr2 = _setup_dma_stream(dma, 0, dr_addr, rx2, 2, "p2m")
        tx_cr2 = _setup_dma_stream(dma, 3, dr_addr, tx_addr + 0x10, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr2)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr2)
        spi.write(0x00, 4, spi._CR1_SPE)
        self.assertEqual(emu.mem_read(rx2, 2)[1], 0x47, "second WHOAMI read")

    def test_only_cs_asserted_device_receives_bytes(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        fram = FramFm25v02a(name="fram0")
        spi.attach_device(imu)
        spi.attach_device(fram)

        # Only FRAM is selected.
        fram.cs_select()
        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x9F, 0x00, 0x00, 0x00, 0x00]))
        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 5, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 5, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)
        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        rx = emu.mem_read(rx_addr, 5)
        # FRAM JEDEC pattern, not IMU response.
        self.assertEqual(rx[1], 0x7F)
        # IMU stayed idle (no CS) so its byte counter stays at 0.
        self.assertEqual(imu._bytes_exchanged, 0)


# ── H7-style (TXDR/RXDR + CFG1) ─────────────────────────────────


class H7SpiDmaTests(unittest.TestCase):
    def test_h7_icm42688_whoami_via_cfg1_dma(self):
        bus, spi, dma, _nvic, emu = _make_h7_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))

        rxdr_addr = 0x40013000 + 0x30
        txdr_addr = 0x40013000 + 0x20
        rx_cr = _setup_dma_stream(dma, 0, rxdr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 1, txdr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 1 * 0x18 + dma._SxCR, 4, tx_cr)

        # H7 layout: DMA enables live in CFG1, not CR2.
        spi.write(0x08, 4, spi._H7_CFG1_TXDMAEN | spi._H7_CFG1_RXDMAEN)
        spi.write(0x00, 4, spi._H7_CR1_SPE | spi._H7_CR1_CSTART)

        rx = emu.mem_read(rx_addr, 2)
        self.assertEqual(rx[1], 0x47, "ICM-42688 WHOAMI through H7 DMA")

    def test_h7_full_duplex_dma_with_request_mapping(self):
        # Same full-duplex flow, but with the streams explicitly mapped to the
        # SPI1_RX / SPI1_TX request lines — DMAMUX routing must not break it.
        bus, spi, dma, _nvic, emu = _make_h7_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        tx_addr, rx_addr = 0x100, 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))
        rxdr_addr = 0x40013000 + 0x30
        txdr_addr = 0x40013000 + 0x20
        rx_cr = _setup_dma_stream(dma, 0, rxdr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 1, txdr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 1 * 0x18 + dma._SxCR, 4, tx_cr)
        dma.set_stream_request(0, "SPI1_RX")
        dma.set_stream_request(1, "SPI1_TX")

        spi.write(0x08, 4, spi._H7_CFG1_TXDMAEN | spi._H7_CFG1_RXDMAEN)
        spi.write(0x00, 4, spi._H7_CR1_SPE | spi._H7_CR1_CSTART)

        self.assertEqual(emu.mem_read(rx_addr, 2)[1], 0x47, "WHOAMI via mapped DMA")

    def test_h7_16bit_frame_dma_roundtrip(self):
        # 16-bit SPI frames driven entirely by DMA: CFG1.DSIZE selects 16-bit,
        # the DMA streams use PSIZE=16-bit, so each DMA item is one whole frame
        # (a halfword), not a byte. An echo slave mirrors TX -> RX.
        bus, spi, dma, _nvic, emu = _make_h7_setup()

        class _Echo:
            cs_active = True
            def exchange(self, b):
                return b

        spi.attach_device(_Echo())

        tx_addr, rx_addr = 0x100, 0x200
        emu.mem_write(tx_addr, bytes([0x34, 0x12, 0x78, 0x56]))  # 0x1234, 0x5678
        rxdr = 0x40013000 + 0x30
        txdr = 0x40013000 + 0x20
        psize16 = 1  # 1 << 1 = 2 bytes

        def _cr16(stream, par, mar, ndtr, direction):
            so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
            dma.write_register_value(so + dma._SxNDTR, ndtr)
            dma.write_register_value(so + dma._SxPAR, par)
            dma.write_register_value(so + dma._SxM0AR, mar)
            return (
                dma._SxCR_EN | dma._SxCR_MINC
                | (direction << dma._SxCR_DIR_SHIFT)
                | (psize16 << dma._SxCR_PSIZE_SHIFT)
                | (psize16 << dma._SxCR_MSIZE_SHIFT)
            )

        rx_cr = _cr16(0, rxdr, rx_addr, 2, dma._DIR_P2M)
        tx_cr = _cr16(1, txdr, tx_addr, 2, dma._DIR_M2P)
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 1 * 0x18 + dma._SxCR, 4, tx_cr)

        spi.write(0x08, 4, 15 | spi._H7_CFG1_TXDMAEN | spi._H7_CFG1_RXDMAEN)  # DSIZE=15
        spi.write(0x00, 4, spi._H7_CR1_SPE | spi._H7_CR1_CSTART)

        # Echo slave returns each frame unchanged, so RX memory mirrors TX.
        self.assertEqual(emu.mem_read(rx_addr, 4), bytes([0x34, 0x12, 0x78, 0x56]))

    def test_h7_16bit_frame_sends_both_bytes(self):
        # CFG1.DSIZE = 15 selects 16-bit frames; a TXDR write must clock out
        # both bytes (MSB first) and RXDR must return the reassembled frame.
        bus, spi, dma, _nvic, emu = _make_h7_setup()
        spi.write(0x08, 4, 15)  # CFG1.DSIZE = 15 -> 16-bit

        class _Echo:
            cs_active = True
            def exchange(self, b):
                return b

        spi.attach_device(_Echo())
        spi.write(0x20, 4, 0x1234)  # TXDR
        self.assertEqual(spi.drain_tx(), bytes([0x12, 0x34]))
        self.assertEqual(spi.read(0x30, 4), 0x1234)  # RXDR

    def test_h7_eot_clears_via_ifcr_and_stays_clear(self):
        # EOT must be a latched flag: set on transfer completion, cleared by
        # writing EOTC to IFCR, and it must NOT immediately re-assert on the
        # next SR read (which would stall firmware polling on EOT).
        bus, spi, dma, _nvic, emu = _make_h7_setup()
        spi.write(0x00, 4, spi._H7_CR1_SPE | spi._H7_CR1_CSTART)
        self.assertTrue(spi.read(0x14, 4) & spi._H7_SR_EOT, "CSTART latches EOT")

        spi.write(0x18, 4, spi._H7_IFCR_EOTC)  # IFCR.EOTC
        self.assertFalse(spi.read(0x14, 4) & spi._H7_SR_EOT, "EOTC clears EOT")
        self.assertFalse(spi.read(0x14, 4) & spi._H7_SR_EOT, "EOT stays clear")


# ── Snapshot of in-progress transfer + device state ─────────────


class SpiDmaOrderingTests(unittest.TestCase):
    """Firmware-order independence for SPI DMA setup."""

    def test_spi_enabled_before_streams_armed(self):
        # Reverse of the common ChibiOS order: firmware enables SPI with
        # DMAEN first, then programs and enables the DMA streams. The
        # initial TX kick from CR1/CR2 fired into the void, so the stream
        # arm has to re-pull the request.
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        # SPI: DMA bits and SPE FIRST.
        spi.write(0x04, 4, spi._CR2_TXDMAEN | spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)

        # Then the streams.
        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0x80 | 0x75, 0x00]))
        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m", tcie=True)
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)

        # No further SPI writes after this — the transfer must self-start
        # from the stream-arm kick.
        rx = emu.mem_read(rx_addr, 2)
        self.assertEqual(rx[1], 0x47, "WHOAMI arrives when streams are armed last")

    def test_stream_arm_kick_only_when_spi_enabled(self):
        # If SPI is NOT enabled, arming the stream must not trigger a
        # transfer (would otherwise clock garbage into an unselected slave).
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        imu = Icm42688Device(name="icm")
        imu.cs_select()
        spi.attach_device(imu)

        tx_addr = 0x100
        rx_addr = 0x200
        emu.mem_write(tx_addr, bytes([0xAA, 0xBB]))
        dr_addr = 0x40013000 + 0x0C
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, rx_addr, 2, "p2m")
        tx_cr = _setup_dma_stream(dma, 3, dr_addr, tx_addr, 2, "m2p")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        dma.write(0x10 + 3 * 0x18 + dma._SxCR, 4, tx_cr)
        # SPI is silent — no CR1.SPE, no CR2 DMAEN.

        rx = emu.mem_read(rx_addr, 2)
        self.assertEqual(rx, b"\x00\x00", "no transfer when SPI is disabled")
        self.assertEqual(imu._bytes_exchanged, 0)


class DmaHalfEventBytesTests(unittest.TestCase):
    def test_dma_half_reports_half_buffer_bytes(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        bus.event_log_enabled = True

        dr_addr = 0x40013000 + 0x0C
        # 8-byte circular RX buffer; HTIF should fire at byte 4.
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, 0x300, 8, "p2m")
        rx_cr |= dma._SxCR_CIRC
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)

        # SPI in DMA mode so inject_rx emits per-byte requests.
        spi.write(0x04, 4, spi._CR2_RXDMAEN)
        spi.write(0x00, 4, spi._CR1_SPE)
        bus.drain_event_log()

        spi.inject_rx(bytes(range(4)))

        log = bus.drain_event_log()
        half = [e for e in log if e.kind == "dma_half"]
        self.assertEqual(len(half), 1)
        # Half mark of an 8-item byte-sized buffer = 4 bytes transferred.
        self.assertEqual(half[0].payload["bytes"], 4)
        self.assertEqual(half[0].payload["stream"], 0)


class SpiDmaSnapshotTests(unittest.TestCase):
    def test_snapshot_preserves_dma_progress_and_device_state(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        fram = FramFm25v02a(name="fram0")
        spi.attach_device(fram)
        fram.cs_select()

        # Issue an RDID with one stalled byte (write directly so we can
        # observe in-flight state without driving DMA to completion).
        spi.write(0x0C, 4, 0x9F)  # RDID opcode
        self.assertEqual(fram._state, "RDID_DATA")
        # Capture mid-transaction snapshot from the bus.
        state = bus.snapshot_models_state()
        # Reset both peripherals and the FRAM to verify restore.
        spi.reset()
        # spi.reset() does not clear attached devices, so we can also reset
        # the FRAM directly to drop its in-progress frame.
        fram.reset()
        self.assertEqual(fram._state, "IDLE")

        # Restore and verify the FRAM is back in mid-RDID with CS still
        # asserted, ready to clock out the next JEDEC byte.
        bus.restore_models_state(state)
        self.assertEqual(fram._state, "RDID_DATA")
        self.assertTrue(fram.cs_active)
        # Drain the in-flight RX byte (0xFF echo of the opcode) that the
        # snapshot preserved, then clock the next byte and read JEDEC[0].
        _ = spi.read(0x0C, 4)
        spi.write(0x0C, 4, 0x00)
        rx = spi.read(0x0C, 4)
        self.assertEqual(rx, 0x7F)

    def test_snapshot_preserves_in_progress_stream_position(self):
        bus, spi, dma, _nvic, emu = _make_legacy_setup()
        # Configure a non-circular RX stream but don't enable it through
        # the SPI yet. Manually drive a couple of items via on_peripheral_request
        # to leave the stream half-way through, then snapshot and restore.
        dr_addr = 0x40013000 + 0x0C
        # Pre-fill SPI RX so DMA has something to drain.
        spi.inject_rx(bytes([0xAA, 0xBB, 0xCC, 0xDD]))
        rx_cr = _setup_dma_stream(dma, 0, dr_addr, 0x300, 4, "p2m")
        dma.write(0x10 + 0 * 0x18 + dma._SxCR, 4, rx_cr)
        # Drive two items.
        dma.on_peripheral_request(dr_addr, "p2m")
        dma.on_peripheral_request(dr_addr, "p2m")

        state = bus.snapshot_models_state()
        # Clear DMA's progress and verify restore brings it back.
        dma._stream_pos[0] = 0
        dma._stream_ndtr_reload[0] = 0
        bus.restore_models_state(state)
        self.assertEqual(dma._stream_pos[0], 2)
        self.assertEqual(dma._stream_ndtr_reload[0], 4)


if __name__ == "__main__":
    unittest.main()
