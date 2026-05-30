"""Tests for the declarative register-file primitives (B1)."""
from __future__ import annotations

import unittest

from stmemu.external.register_file import Register, RegisterFile


def _rf():
    return RegisterFile([
        Register(0x75, "WHO_AM_I", "ro", reset=0x47),
        Register(0x1F, "INT_STATUS", "w1c", reset=0xFF),
        Register(0x3F, "FIFO_DATA", "fifo"),
        Register(0x4E, "PWR_MGMT0"),                 # rw
        Register(0x10, "TEMP16", "rw", mask=0xFFFF),
    ], default=0)


class RegisterFileTest(unittest.TestCase):
    def test_rw(self):
        rf = _rf()
        rf.write(0x4E, 0xA5)
        self.assertEqual(rf.read(0x4E), 0xA5)
        rf.write(0x4E, 0x123)            # masked to 8 bits
        self.assertEqual(rf.read(0x4E), 0x23)

    def test_ro_ignores_writes(self):
        rf = _rf()
        self.assertEqual(rf.read(0x75), 0x47)
        rf.write(0x75, 0x00)             # ignored
        self.assertEqual(rf.read(0x75), 0x47)

    def test_w1c_clears_written_bits(self):
        rf = _rf()
        self.assertEqual(rf.read(0x1F), 0xFF)
        rf.write(0x1F, 0x01)             # clear bit 0
        self.assertEqual(rf.read(0x1F), 0xFE)
        rf.write(0x1F, 0xF0)             # clear top nibble
        self.assertEqual(rf.read(0x1F), 0x0E)

    def test_fifo_streams_without_increment(self):
        rf = _rf()
        rf.feed_fifo(0x3F, bytes([0x68, 0x11, 0x22]))
        self.assertEqual(rf.fifo_len(0x3F), 3)
        self.assertEqual(rf.read(0x3F), 0x68)     # same offset, successive bytes
        self.assertEqual(rf.read(0x3F), 0x11)
        self.assertEqual(rf.read(0x3F), 0x22)
        self.assertEqual(rf.read(0x3F), 0x00)     # empty -> default
        rf.write(0x3F, 0xAB)                      # writes to a fifo are ignored
        self.assertEqual(rf.read(0x3F), 0x00)

    def test_wide_register_mask(self):
        rf = _rf()
        rf.write(0x10, 0x1234)
        self.assertEqual(rf.read(0x10), 0x1234)
        rf.write(0x10, 0x1FFFF)
        self.assertEqual(rf.read(0x10), 0xFFFF)

    def test_describe_and_unknown(self):
        rf = _rf()
        self.assertEqual(rf.describe(0x75), "WHO_AM_I")
        self.assertIsNone(rf.describe(0xAA))
        self.assertFalse(rf.has(0xAA))
        self.assertEqual(rf.read(0xAA), 0)        # unknown -> default
        rf.write(0xAA, 0x55)                      # unknown write ignored (no raise)

    def test_set_get_backdoor_bypasses_ro(self):
        rf = _rf()
        rf.set(0x75, 0x99)                        # device-side, bypasses ro
        self.assertEqual(rf.get(0x75), 0x99)
        self.assertEqual(rf.read(0x75), 0x99)

    def test_reset_restores_values_and_clears_fifo(self):
        rf = _rf()
        rf.write(0x4E, 0x12)
        rf.feed_fifo(0x3F, b"\x01\x02")
        rf.reset()
        self.assertEqual(rf.read(0x4E), 0x00)
        self.assertEqual(rf.read(0x1F), 0xFF)     # back to reset
        self.assertEqual(rf.fifo_len(0x3F), 0)

    def test_snapshot_restore_roundtrip(self):
        rf = _rf()
        rf.write(0x4E, 0x77)
        rf.feed_fifo(0x3F, b"\xAA\xBB")
        st = rf.snapshot_state()
        rf2 = _rf()
        rf2.restore_state(st)
        self.assertEqual(rf2.read(0x4E), 0x77)
        self.assertEqual(rf2.read(0x3F), 0xAA)
        self.assertEqual(rf2.read(0x3F), 0xBB)

    def test_read_dummy_flag(self):
        rf = RegisterFile([Register(0x00, "X")], read_dummy=True)
        self.assertTrue(rf.read_dummy)

    def test_bad_kind_raises(self):
        with self.assertRaises(ValueError):
            Register(0x00, "X", "bogus")


if __name__ == "__main__":
    unittest.main()
