"""Runtime DMAMUX routing tests.

The DMAMUX models DMAMUX1/DMAMUX2 as real MMIO peripherals: firmware writes a
channel's CxCR with a DMAREQ_ID, the model maps it to a symbolic request line
(SPI1_RX, ...) and programs the target DMA stream via set_stream_request(). This
exercises that firmware-visible path (register writes), not the static
set_stream_request()/YAML overlay path.
"""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus, PeripheralModel
from stmemu.peripherals.dma import build_dma, DmaPeripheral, _H7_DMA_IRQS
from stmemu.peripherals.dmamux import build_dmamux


class _FakeEmu:
    def __init__(self, size: int = 0x1000):
        self._mem = bytearray(size)

    def mem_write(self, addr, data):
        self._mem[addr & 0xFFF:(addr & 0xFFF) + len(data)] = data

    def mem_read(self, addr, size):
        off = addr & 0xFFF
        return bytes(self._mem[off:off + size])


class _FakeNvic:
    def set_irq_pending(self, *a, **k):
        pass

    def set_system_pending(self, *a, **k):
        pass


class _Src(PeripheralModel):
    def __init__(self, value=0xA5):
        self.value = value

    def read(self, offset, size):
        return self.value & ((1 << (size * 8)) - 1)

    def write(self, offset, size, value):
        pass


_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
)

_BASES = {
    "DMA1": 0x40020000,
    "DMA2": 0x40020400,
    "BDMA": 0x58025400,
    "DMAMUX1": 0x40020800,
    "DMAMUX2": 0x58025800,
    "SPI1": 0x40013000,
}
_DR = 0x40


def _svd(name, regs=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=_BASES[name], size=0x400,
        registers=regs, interrupts=interrupts,
    )


def _build():
    specs = {
        "DMA1": (_svd("DMA1", _DMA_REGS), build_dma),
        "DMA2": (_svd("DMA2", _DMA_REGS), build_dma),
        "BDMA": (_svd("BDMA", _DMA_REGS), build_dma),
        "DMAMUX1": (_svd("DMAMUX1"), build_dmamux),
        "DMAMUX2": (_svd("DMAMUX2"), build_dmamux),
        "SPI1": (_svd("SPI1", (SvdRegister(name="DR", offset=_DR),)), None),
    }
    svds = [s for s, _ in specs.values()]
    ranges = tuple(
        AddressRange(base=s.base_address, end=s.base_address + 0x400, peripheral=s)
        for s in svds
    )
    amap = AddressMap(device_name="T", peripherals=tuple(svds), ranges=ranges)
    bus = PeripheralBus(amap)
    bus._interrupts = _FakeNvic()
    bus._emulator = _FakeEmu()
    models = {}
    for name, (svd, builder) in specs.items():
        model = builder(svd) if builder else _Src()
        bus.register_peripheral(name, model)
        models[name] = model
    return bus, models


def _cxcr_offset(channel: int) -> int:
    return channel * 4


class DmaMuxRoutingTests(unittest.TestCase):
    def test_c0cr_req37_maps_dma1_stream0_spi1_rx(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 37)
        self.assertEqual(m["DMA1"]._stream_request.get(0), "SPI1_RX")

    def test_c8cr_req38_maps_dma2_stream0_spi1_tx(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(8), 4, 38)
        self.assertEqual(m["DMA2"]._stream_request.get(0), "SPI1_TX")

    def test_dmamux2_c0cr_req3_maps_bdma_stream0_spi6_rx(self):
        bus, m = _build()
        m["DMAMUX2"].write(_cxcr_offset(0), 4, 3)
        self.assertEqual(m["BDMA"]._stream_request.get(0), "SPI6_RX")

    def test_cxcr_write_zero_clears_mapping(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 37)
        self.assertEqual(m["DMA1"]._stream_request.get(0), "SPI1_RX")
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 0)
        self.assertNotIn(0, m["DMA1"]._stream_request)

    def test_remap_changes_request(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 37)  # SPI1_RX
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 47)  # USART3_RX
        self.assertEqual(m["DMA1"]._stream_request.get(0), "USART3_RX")

    def test_unknown_request_id_falls_back_to_symbolic(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(1), 4, 200)  # not in the table
        self.assertEqual(m["DMA1"]._stream_request.get(1), "REQ200")


class DmaMuxEndToEndTests(unittest.TestCase):
    """A real DMA transfer whose routing was created by a DMAMUX register write."""

    def _arm(self, dma, stream, mar, ndtr=1):
        so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
        dma.write_register_value(so + dma._SxNDTR, ndtr)
        dma.write_register_value(so + dma._SxPAR, _BASES["SPI1"] + _DR)
        dma.write_register_value(so + dma._SxM0AR, mar)
        dma.write(so + dma._SxCR, 4, dma._SxCR_EN | dma._SxCR_MINC)

    def _ndtr(self, dma, stream):
        so = dma._STREAM_BASE + stream * dma._STREAM_STRIDE
        return dma.read_register_value(so + dma._SxNDTR)

    def test_transfer_uses_runtime_dmamux_mapping(self):
        bus, m = _build()
        dma, mux, emu = m["DMA1"], m["DMAMUX1"], bus._emulator
        # Map SPI1_RX onto DMA1 stream0 purely via the MMIO register write.
        mux.write(_cxcr_offset(0), 4, 37)
        self._arm(dma, 0, mar=0x200)

        # A mismatched request is blocked (the mapping is live)...
        dma.on_peripheral_request(_BASES["SPI1"] + _DR, "p2m", 1, request="USART3_RX")
        self.assertEqual(self._ndtr(dma, 0), 1)
        # ...the mapped request transfers.
        dma.on_peripheral_request(_BASES["SPI1"] + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(self._ndtr(dma, 0), 0)
        self.assertEqual(emu.mem_read(0x200, 1), bytes([0xA5]))

    def test_snapshot_restore_preserves_runtime_mapping(self):
        bus, m = _build()
        m["DMAMUX1"].write(_cxcr_offset(0), 4, 37)  # SPI1_RX via MMIO
        snap = m["DMA1"].snapshot_state()

        bus2, m2 = _build()
        m2["DMA1"].restore_state(snap)
        self.assertEqual(m2["DMA1"]._stream_request.get(0), "SPI1_RX")
        # And it routes: wrong request blocked, mapped one transfers.
        self._arm(m2["DMA1"], 0, mar=0x200)
        m2["DMA1"].on_peripheral_request(_BASES["SPI1"] + _DR, "p2m", 1, request="SPI1_TX")
        self.assertEqual(self._ndtr(m2["DMA1"], 0), 1)
        m2["DMA1"].on_peripheral_request(_BASES["SPI1"] + _DR, "p2m", 1, request="SPI1_RX")
        self.assertEqual(self._ndtr(m2["DMA1"], 0), 0)


class DmaIrqFallbackTests(unittest.TestCase):
    def test_fallback_irqs_when_svd_has_no_stream_names(self):
        dma1 = build_dma(_svd("DMA1", _DMA_REGS))
        self.assertEqual(dma1._irqs, _H7_DMA_IRQS["DMA1"])
        bdma = build_dma(_svd("BDMA", _DMA_REGS))
        self.assertEqual(bdma._irqs, _H7_DMA_IRQS["BDMA"])

    def test_self_named_interrupt_overrides_fallback(self):
        dma2 = build_dma(_svd(
            "DMA2", _DMA_REGS,
            interrupts=(SvdInterrupt(name="DMA2_STR3", value=999),),
        ))
        self.assertEqual(dma2._irqs[3], 999, "self-named stream IRQ wins")
        # Other streams still resolve through the fixed H7 fallback table.
        self.assertEqual(dma2._irqs[0], _H7_DMA_IRQS["DMA2"][0])


if __name__ == "__main__":
    unittest.main()
