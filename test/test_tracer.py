"""Unit tests for the decoded bus-transaction tracer."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.peripherals.tracer import BusTracer  # noqa: E402


def feed(tr, recs):
    for r in recs:
        tr.record(r)


class TracerTest(unittest.TestCase):
    def test_spi_read_coalesced_and_decoded(self):
        tr = BusTracer()
        # ICM WHOAMI read: cmd 0x75|0x80, dummy miso, then data byte 0x47.
        feed(tr, [
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0xF5, "miso": 0xFF},
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0x00, "miso": 0x47},
        ])
        out = tr.dump()
        self.assertIn("icm42688", out)
        self.assertIn("rd reg=0x75", out)
        self.assertIn("47", out)
        # One coalesced line, not two per-byte lines.
        self.assertEqual(len(tr.lines), 1)

    def test_spi_run_splits_on_device_change(self):
        tr = BusTracer()
        feed(tr, [
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0xF5, "miso": 0xFF},
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0x00, "miso": 0x47},
            {"proto": "spi", "bus": "SPI1", "device": "bmi088_g", "mosi": 0x80, "miso": 0xFF},
            {"proto": "spi", "bus": "SPI1", "device": "bmi088_g", "mosi": 0x00, "miso": 0x0F},
        ])
        out = tr.dump()
        self.assertEqual(len(tr.lines), 2)
        self.assertIn("bmi088_g", out)
        self.assertIn("0f", out)

    def test_spi_write_shows_mosi(self):
        tr = BusTracer()
        # Write to reg 0x7E value 0xB6 (cmd has bit7 clear).
        feed(tr, [
            {"proto": "spi", "bus": "SPI1", "device": "bmi088_g", "mosi": 0x7E, "miso": 0xFF},
            {"proto": "spi", "bus": "SPI1", "device": "bmi088_g", "mosi": 0xB6, "miso": 0xFF},
        ])
        out = tr.dump()
        self.assertIn("wr reg=0x7e", out)
        self.assertIn("b6", out)

    def test_i2c_and_uart_lines(self):
        tr = BusTracer()
        feed(tr, [
            {"proto": "i2c", "bus": "I2C4", "addr": 0x76, "rw": "wr", "nbytes": 1, "ack": True},
            {"proto": "i2c", "bus": "I2C4", "addr": 0x77, "rw": "rd", "nbytes": 3, "ack": False},
            {"proto": "uart", "bus": "UART5", "device": "ublox", "dir": "tx", "bytes": b"\xb5\x62\x06"},
        ])
        out = tr.dump()
        self.assertIn("0x76 wr nbytes=1 ACK", out)
        self.assertIn("0x77 rd nbytes=3 NACK", out)
        self.assertIn("UART5", out)
        self.assertIn("tx 3B", out)
        self.assertIn("b5 62 06", out)

    def test_source_filter_by_bus_or_device(self):
        tr = BusTracer(sources=["SPI1", "ublox"])
        feed(tr, [
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0xF5, "miso": 0xFF},
            {"proto": "spi", "bus": "SPI1", "device": "icm42688", "mosi": 0x00, "miso": 0x47},
            {"proto": "i2c", "bus": "I2C4", "addr": 0x76, "rw": "wr", "nbytes": 1, "ack": True},
            {"proto": "uart", "bus": "UART5", "device": "ublox", "dir": "rx", "bytes": b"\x01"},
        ])
        out = tr.dump()
        self.assertIn("icm42688", out)   # SPI1 matched by bus name
        self.assertIn("ublox", out)      # UART matched by device name
        self.assertNotIn("0x76", out)    # I2C4 filtered out

    def test_limit_and_dropped_surfaced(self):
        tr = BusTracer(limit=3)
        for i in range(10):
            tr.record({"proto": "i2c", "bus": "I2C4", "addr": i, "rw": "rd", "nbytes": 0, "ack": True})
        out = tr.dump()
        self.assertEqual(len(tr.lines), 3)
        self.assertGreater(tr.dropped, 0)
        self.assertIn("dropped", out)

    def test_counts(self):
        tr = BusTracer()
        feed(tr, [
            {"proto": "i2c", "bus": "I2C4", "addr": 0x76, "rw": "wr", "nbytes": 1, "ack": True},
            {"proto": "i2c", "bus": "I2C4", "addr": 0x76, "rw": "rd", "nbytes": 2, "ack": True},
        ])
        counts = tr.counts()
        self.assertEqual(counts.get("I2C4 0x76"), 2)


if __name__ == "__main__":
    unittest.main()
