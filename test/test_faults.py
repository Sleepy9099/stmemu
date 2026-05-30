"""Unit tests for deterministic device fault injection."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.external.faults import FaultRule, FaultySpiDevice, FaultySerialDevice  # noqa: E402


class _FakeSpi:
    """Minimal SPI slave: byte0 = addr (returns 0xFF), data bytes return `data`."""
    def __init__(self, data=0x47):
        self.name = "fake"
        self.cs_active = True
        self._data = data
        self._first = True

    def cs_select(self):
        self._first = True

    def cs_release(self):
        pass

    def exchange(self, mosi):
        if self._first:
            self._first = False
            return 0xFF
        return self._data


def spi_read(dev, addr, n=1):
    """Run one CS transaction: address byte then n data bytes; return data MISO."""
    dev.cs_select()
    dev.exchange(0x80 | addr)
    out = [dev.exchange(0x00) for _ in range(n)]
    dev.cs_release()
    return out


class _FakeSerial:
    def __init__(self, chunks):
        self.name = "gps"
        self._chunks = list(chunks)
        self.rx = []

    def on_rx_from_mcu(self, data):
        self.rx.append(bytes(data))

    def read_tx_to_mcu(self, max_bytes=4096):
        return self._chunks.pop(0) if self._chunks else b""


class FaultSpiTest(unittest.TestCase):
    def test_stuck_overrides_data_byte(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00)])
        self.assertEqual(spi_read(dev, 0x75), [0x00])
        self.assertEqual(dev.faults_applied, 1)

    def test_corrupt_xor_mask(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="corrupt", reg=0x75, mask=0xFF)])
        self.assertEqual(spi_read(dev, 0x75), [0x47 ^ 0xFF])

    def test_reg_filter_spares_other_registers(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00)])
        self.assertEqual(spi_read(dev, 0x10), [0x47])   # different reg -> untouched
        self.assertEqual(spi_read(dev, 0x75), [0x00])   # matching reg -> faulted

    def test_address_byte_never_faulted(self):
        # A rule with no reg filter still must not corrupt the address echo byte.
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", value=0xAA)])
        dev.cs_select()
        addr_echo = dev.exchange(0x80 | 0x75)
        data = dev.exchange(0x00)
        self.assertEqual(addr_echo, 0xFF)   # address byte passes through
        self.assertEqual(data, 0xAA)        # data byte faulted

    def test_every_n_transactions(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00, when="every", every=3)])
        # transactions 0,3,6 faulted; 1,2,4,5 clean
        results = [spi_read(dev, 0x75)[0] for _ in range(7)]
        self.assertEqual(results, [0x00, 0x47, 0x47, 0x00, 0x47, 0x47, 0x00])

    def test_once_at_index(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00, when="once", after=2)])
        results = [spi_read(dev, 0x75)[0] for _ in range(5)]
        self.assertEqual(results, [0x47, 0x47, 0x00, 0x47, 0x47])

    def test_limit_caps_fires(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00, when="after", limit=2)])
        results = [spi_read(dev, 0x75)[0] for _ in range(5)]
        self.assertEqual(results, [0x00, 0x00, 0x47, 0x47, 0x47])
        self.assertEqual(dev.faults_applied, 2)

    def test_reset_restores_rule_counters(self):
        dev = FaultySpiDevice(_FakeSpi(0x47), [FaultRule(kind="stuck", reg=0x75, value=0x00, when="once", after=0)])
        self.assertEqual(spi_read(dev, 0x75), [0x00])
        dev.reset()
        self.assertEqual(spi_read(dev, 0x75), [0x00])  # index restarts at 0 -> fires again


class FaultSerialTest(unittest.TestCase):
    def test_drop_chunk(self):
        inner = _FakeSerial([b"\xb5\x62", b"\x01\x02", b"\x03"])
        dev = FaultySerialDevice(inner, [FaultRule(kind="drop", when="once", after=1)])
        self.assertEqual(dev.read_tx_to_mcu(), b"\xb5\x62")  # chunk 0 ok
        self.assertEqual(dev.read_tx_to_mcu(), b"")          # chunk 1 dropped
        self.assertEqual(dev.read_tx_to_mcu(), b"\x03")      # chunk 2 ok
        self.assertEqual(dev.faults_applied, 1)

    def test_corrupt_chunk_bytes(self):
        inner = _FakeSerial([b"\x01\x02\x03"])
        dev = FaultySerialDevice(inner, [FaultRule(kind="corrupt", mask=0xFF)])
        self.assertEqual(dev.read_tx_to_mcu(), bytes([0xFE, 0xFD, 0xFC]))

    def test_mcu_to_device_passes_through(self):
        inner = _FakeSerial([])
        dev = FaultySerialDevice(inner, [FaultRule(kind="drop")])
        dev.on_rx_from_mcu(b"\xb5\x62\x06")
        self.assertEqual(inner.rx, [b"\xb5\x62\x06"])


class FaultConfigTest(unittest.TestCase):
    def test_parse_fault_rules_from_yaml_cfg(self):
        from stmemu.board_config import _parse_fault_rules
        cfg = {"faults": [
            {"kind": "stuck", "reg": "0x75", "value": "0x00", "when": "once", "after": 5},
            {"kind": "corrupt", "mask": "0x0F", "every": 10, "limit": 3},
        ]}
        rules = _parse_fault_rules(cfg)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].kind, "stuck")
        self.assertEqual(rules[0].reg, 0x75)
        self.assertEqual(rules[0].value, 0x00)
        self.assertEqual(rules[0].when, "once")
        self.assertEqual(rules[0].after, 5)
        self.assertEqual(rules[1].kind, "corrupt")
        self.assertEqual(rules[1].mask, 0x0F)
        self.assertEqual(rules[1].limit, 3)
        self.assertIsNone(rules[1].reg)   # no reg filter

    def test_no_faults_key_yields_empty(self):
        from stmemu.board_config import _parse_fault_rules
        self.assertEqual(_parse_fault_rules({}), [])
        self.assertEqual(_parse_fault_rules({"faults": []}), [])


if __name__ == "__main__":
    unittest.main()
