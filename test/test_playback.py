"""Unit tests for the cycle-paced playback device."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.external.playback import PlaybackSerialDevice  # noqa: E402


class PlaybackTest(unittest.TestCase):
    def test_paces_one_byte_per_tick_window(self):
        d = PlaybackSerialDevice(data=b"ABCDE", tick_cycles=100, bytes_per_tick=1)
        self.assertEqual(d.read_tx_to_mcu(), b"")     # no time yet
        d.tick(100)
        self.assertEqual(d.read_tx_to_mcu(), b"A")
        d.tick(250)                                    # 2 full windows + remainder
        self.assertEqual(d.read_tx_to_mcu(), b"BC")
        self.assertEqual(d.read_tx_to_mcu(), b"")      # remainder not enough for next

    def test_bytes_per_tick(self):
        d = PlaybackSerialDevice(data=b"ABCDEF", tick_cycles=10, bytes_per_tick=3)
        d.tick(10)
        self.assertEqual(d.read_tx_to_mcu(), b"ABC")

    def test_one_shot_exhausts(self):
        d = PlaybackSerialDevice(data=b"AB", tick_cycles=1, bytes_per_tick=10)
        d.tick(5)
        self.assertEqual(d.read_tx_to_mcu(), b"AB")
        d.tick(5)
        self.assertEqual(d.read_tx_to_mcu(), b"")      # exhausted, no loop

    def test_loop_wraps(self):
        d = PlaybackSerialDevice(data=b"AB", tick_cycles=1, bytes_per_tick=1, loop=True)
        d.tick(5)
        self.assertEqual(d.read_tx_to_mcu(), b"ABABA")  # wraps repeatedly

    def test_records_mcu_traffic(self):
        d = PlaybackSerialDevice(data=b"", tick_cycles=1)
        d.on_rx_from_mcu(b"\xb5\x62\x06\x00")
        self.assertEqual(bytes(d.received), b"\xb5\x62\x06\x00")

    def test_snapshot_restore(self):
        d = PlaybackSerialDevice(data=b"ABCDE", tick_cycles=10, bytes_per_tick=1)
        d.tick(20)
        self.assertEqual(d.read_tx_to_mcu(), b"AB")
        snap = d.snapshot_state()
        d2 = PlaybackSerialDevice(data=b"ABCDE", tick_cycles=10, bytes_per_tick=1)
        d2.restore_state(snap)
        d2.tick(10)
        self.assertEqual(d2.read_tx_to_mcu(), b"C")     # resumes after B


if __name__ == "__main__":
    unittest.main()
